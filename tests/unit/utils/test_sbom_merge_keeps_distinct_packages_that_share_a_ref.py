# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A merged SBOM keeps distinct packages that share a reference id.

Why this exists
---------------
CycloneDX promises that a ``bom-ref`` is unique within one BOM, and nothing across
two. syft's refs carry the package URL and a content hash, so two syft runs agree on
them. ``scan_result_processor`` hands every scanner's CycloneDX report to the merge,
and a generator that numbers its refs per document ("1", "component-1") gives two
different packages one ref. The merge matched components on the ref alone, so the
second package was dropped and the second document's ``dependsOn`` edges were united
into the entry of the first one's package.

What the cells pin
------------------
A component of the second report is dropped only when its ``bom-ref`` matches one
the first report holds and the two are the same package. Two components with a
``purl`` are the same package when the ``purl`` is the same. When either has no
``purl`` (generators that number their refs write none for files, operating
systems and vendored code), they are the same package when their ``type``,
``group``, ``name`` and ``version`` are all the same. When the ref matches and the
package does not, both packages are kept: the second one gets a ref no component
and no dependency entry in either document uses, every reference to the old ref in
the second report's ``dependencies`` (``dependsOn`` and ``provides``) follows it.
One merge logs one warning however many refs it re-references: the count and the
first few refs. Each re-referenced package has its own line at debug level. The
merge changes neither input.
"""

from __future__ import annotations

from typing import Any

import pytest

from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
    CycloneDXReport,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports

REQUESTS = "pkg:pypi/requests@2.19.1"
URLLIB3 = "pkg:pypi/urllib3@2.0.0"
FLASK = "pkg:pypi/flask@3.0.0"
JINJA2 = "pkg:pypi/jinja2@3.1.0"
DJANGO = "pkg:pypi/django@5.0.0"
LXML = "pkg:pypi/lxml@5.0.0"


def _component(ref: str, purl: str | None) -> dict[str, Any]:
    component: dict[str, Any] = {
        "type": "library",
        "name": purl.split("/")[-1].split("@")[0] if purl else "unnamed",
        "version": "1.0",
        "bom-ref": ref,
    }
    if purl is not None:
        component["purl"] = purl
    return component


def _plain(
    ref: str,
    name: str,
    version: str = "1.0",
    *,
    group: str | None = None,
    kind: str = "library",
) -> dict[str, Any]:
    """A component with no ``purl``, as a generator that numbers its refs writes it."""
    component: dict[str, Any] = {
        "type": kind,
        "name": name,
        "version": version,
        "bom-ref": ref,
    }
    if group is not None:
        component["group"] = group
    return component


def _dependency(ref: str, **lists: list[str]) -> dict[str, Any]:
    return {"ref": ref, **lists}


def _sbom(
    components: list[dict[str, Any]],
    dependencies: list[dict[str, Any]] | None = None,
) -> CycloneDXReport:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": components,
    }
    if dependencies is not None:
        document["dependencies"] = dependencies
    return CycloneDXReport.model_validate(document)


def _dump(report: CycloneDXReport) -> dict[str, Any]:
    return report.model_dump(by_alias=True, exclude_unset=True, mode="json")


def _merged(held: CycloneDXReport, incoming: CycloneDXReport) -> CycloneDXReport:
    result = merge_cyclonedx_reports(held, incoming)
    assert result is not None
    return result


def _refs_by_purl(report: CycloneDXReport) -> dict[str | None, list[str]]:
    by_purl: dict[str | None, list[str]] = {}
    for component in report.components or []:
        by_purl.setdefault(component.purl, []).append(component.bom_ref.root)
    return by_purl


def _purl_of(report: CycloneDXReport, ref: str) -> str:
    """The purl of the one component that holds *ref*; the ref itself if none does."""
    holders = [c for c in report.components or [] if c.bom_ref.root == ref]
    return holders[0].purl if len(holders) == 1 else ref


def _edges_by_purl(report: CycloneDXReport, field: str) -> dict[str, list[str]]:
    """Each dependency entry read through the packages its refs name, not the refs."""
    return {
        _purl_of(report, dependency.ref.root.root): sorted(
            _purl_of(report, ref.root.root) for ref in getattr(dependency, field) or []
        )
        for dependency in report.dependencies or []
        if getattr(dependency, field)
    }


def test_two_reports_sharing_a_ref_over_different_purls_keep_both_packages():
    held = _sbom([_component("1", REQUESTS)])
    incoming = _sbom([_component("1", FLASK)])

    result = _merged(held, incoming)

    refs = _refs_by_purl(result)
    assert sorted(refs, key=str) == [FLASK, REQUESTS]
    assert refs[REQUESTS] == ["1"]
    assert refs[FLASK] != ["1"]
    assert len({ref for held_refs in refs.values() for ref in held_refs}) == 2


def test_each_further_report_with_the_same_ref_gets_a_ref_of_its_own():
    first = _sbom([_component("1", REQUESTS)])
    second = _sbom([_component("1", FLASK)])
    third = _sbom([_component("1", DJANGO)])

    result = _merged(_merged(first, second), third)

    refs = [component.bom_ref.root for component in result.components]
    assert len(refs) == 3
    assert len(set(refs)) == 3
    assert _refs_by_purl(result)[REQUESTS] == ["1"]


def test_the_new_ref_is_one_that_neither_document_uses():
    held = _sbom([_component("1", REQUESTS), _component("2", URLLIB3)])
    incoming = _sbom([_component("1", FLASK), _component("2", JINJA2)])
    used = {"1", "2"}

    result = _merged(held, incoming)

    refs = _refs_by_purl(result)
    assert refs[REQUESTS] == ["1"]
    assert refs[URLLIB3] == ["2"]
    assert refs[FLASK][0] not in used
    assert refs[JINJA2][0] not in used
    assert refs[FLASK] != refs[JINJA2]


def test_the_second_reports_dependency_edges_follow_the_re_referenced_packages():
    held = _sbom(
        [_component("1", REQUESTS), _component("2", URLLIB3)],
        [_dependency("1", dependsOn=["2"]), _dependency("2")],
    )
    incoming = _sbom(
        [_component("1", FLASK), _component("2", JINJA2)],
        [_dependency("1", dependsOn=["2"]), _dependency("2")],
    )

    result = _merged(held, incoming)

    assert _edges_by_purl(result, "dependsOn") == {
        REQUESTS: [URLLIB3],
        FLASK: [JINJA2],
    }
    assert len(result.dependencies) == 4


def test_provides_follows_the_re_referenced_package_too():
    held = _sbom([_component("1", REQUESTS)])
    incoming = _sbom(
        [_component("1", FLASK), _component("7", LXML)],
        [_dependency("7", provides=["1"])],
    )

    result = _merged(held, incoming)

    assert _edges_by_purl(result, "provides") == {LXML: [FLASK]}


def test_only_the_re_referenced_refs_are_rewritten():
    held = _sbom([_component("1", REQUESTS)])
    incoming = _sbom(
        [_component("1", FLASK), _component("7", LXML)],
        [_dependency("7", dependsOn=["1", "elsewhere"])],
    )

    result = _merged(held, incoming)

    entry = next(d for d in result.dependencies if d.ref.root.root == "7")
    depends_on = [ref.root.root for ref in entry.dependsOn]
    assert depends_on[0] == _refs_by_purl(result)[FLASK][0]
    assert depends_on[1:] == ["elsewhere"]


def test_a_shared_ref_over_the_same_purl_is_still_one_package():
    held = _sbom([_component("1", REQUESTS)], [_dependency("1", dependsOn=["2"])])
    incoming = _sbom([_component("1", REQUESTS)], [_dependency("1", dependsOn=["3"])])

    result = _merged(held, incoming)

    assert _refs_by_purl(result) == {REQUESTS: ["1"]}
    assert [ref.root.root for ref in result.dependencies[0].dependsOn] == ["2", "3"]


def test_a_shared_ref_where_one_side_has_no_purl_keeps_a_different_package():
    held = _sbom([_component("1", REQUESTS)])
    incoming = _sbom([_component("1", None)])

    for first, second in ((held, incoming), (incoming, held)):
        result = _merged(first, second)

        refs = [component.bom_ref.root for component in result.components]
        assert len(refs) == 2
        assert len(set(refs)) == 2
        assert refs[0] == "1"


def test_numbered_refs_over_packages_with_no_purl_keep_both_packages():
    held = _sbom([_plain("1", "libfoo", "1.0")])
    incoming = _sbom([_plain("1", "libbar", "2.0")])

    result = _merged(held, incoming)

    assert [component.name for component in result.components] == ["libfoo", "libbar"]
    refs = [component.bom_ref.root for component in result.components]
    assert refs[0] == "1"
    assert refs[1] != "1"


def test_the_edges_of_a_renumbered_package_stay_off_the_first_one():
    held = _sbom([_plain("1", "libfoo", "1.0")], [_dependency("1")])
    incoming = _sbom(
        [_plain("1", "libbar", "2.0"), _plain("2", "libbaz", "3.0")],
        [_dependency("1", dependsOn=["2"]), _dependency("2")],
    )

    result = _merged(held, incoming)

    by_name = {
        component.name: component.bom_ref.root for component in result.components
    }
    assert len(set(by_name.values())) == 3
    edges = {
        dependency.ref.root.root: [ref.root.root for ref in dependency.dependsOn or []]
        for dependency in result.dependencies
    }
    assert edges[by_name["libfoo"]] == []
    assert edges[by_name["libbar"]] == [by_name["libbaz"]]


@pytest.mark.parametrize("side", ["held", "incoming"])
def test_a_shared_ref_with_the_same_type_group_name_and_version_is_one_package(side):
    plain = _plain("1", "libfoo", "1.0", group="org.example")
    with_purl = {**plain, "purl": "pkg:generic/org.example/libfoo@1.0"}
    held, incoming = (with_purl, plain) if side == "held" else (plain, with_purl)

    result = _merged(_sbom([held]), _sbom([incoming]))

    assert len(result.components) == 1
    assert result.components[0].bom_ref.root == "1"


def test_two_components_with_no_purl_and_the_same_identity_are_one_package():
    held = _sbom([_plain("1", "libfoo", "1.0", group="org.example")])
    incoming = _sbom([_plain("1", "libfoo", "1.0", group="org.example")])

    assert len(_merged(held, incoming).components) == 1


@pytest.mark.parametrize(
    "different",
    [
        {"name": "libbar"},
        {"version": "2.0"},
        {"group": "org.other"},
        {"kind": "framework"},
    ],
    ids=["name", "version", "group", "type"],
)
def test_a_shared_ref_with_no_purl_is_a_new_package_when_one_field_differs(different):
    base = {
        "name": "libfoo",
        "version": "1.0",
        "group": "org.example",
        "kind": "library",
    }
    held = _sbom([_plain("1", **base)])
    incoming = _sbom([_plain("1", **{**base, **different})])

    result = _merged(held, incoming)

    refs = [component.bom_ref.root for component in result.components]
    assert len(refs) == 2
    assert len(set(refs)) == 2


def test_a_re_reference_changes_neither_input():
    held = _sbom([_component("1", REQUESTS)], [_dependency("1", dependsOn=["2"])])
    incoming = _sbom([_component("1", FLASK)], [_dependency("1", dependsOn=["2"])])
    before = (_dump(held), _dump(incoming))

    result = _merged(held, incoming)

    assert (_dump(held), _dump(incoming)) == before
    assert result is not held and result is not incoming
    result.components[1].name = "changed"
    result.dependencies[1].dependsOn[0].root.root = "changed"
    assert (_dump(held), _dump(incoming)) == before


def test_a_warning_names_the_shared_ref(monkeypatch):
    lines: list[str] = []
    monkeypatch.setattr(
        ASH_LOGGER,
        "warning",
        lambda message, *args, **kwargs: lines.append(
            str(message) % args if args else str(message)
        ),
    )
    held = _sbom([_component("component-17", REQUESTS)])
    incoming = _sbom([_component("component-17", FLASK)])

    _merged(held, incoming)

    assert any("component-17" in line for line in lines)


def _logged(monkeypatch, level: str) -> list[str]:
    """Collect what ``ASH_LOGGER`` is asked to log at *level*."""
    lines: list[str] = []
    monkeypatch.setattr(
        ASH_LOGGER,
        level,
        lambda message, *args, **kwargs: lines.append(
            str(message) % args if args else str(message)
        ),
    )
    return lines


def _numbered(count: int, kind: str) -> CycloneDXReport:
    """*count* components with the refs "1" to "<count>" and a purl of *kind* each."""
    return _sbom(
        [_component(str(n), f"pkg:pypi/{kind}{n}@1.0") for n in range(1, count + 1)]
    )


def test_a_merge_with_many_shared_refs_logs_one_warning_with_the_count(monkeypatch):
    warnings = _logged(monkeypatch, "warning")

    result = _merged(_numbered(12, "held"), _numbered(12, "other"))

    assert len(result.components) == 24
    assert len(warnings) == 1
    assert "12" in warnings[0]


def test_the_warning_names_only_the_first_few_shared_refs(monkeypatch):
    warnings = _logged(monkeypatch, "warning")

    _merged(_numbered(12, "held"), _numbered(12, "other"))

    assert "'1', '2', '3'" in warnings[0]
    assert "'4'" not in warnings[0]
    assert "9 more" in warnings[0]


def test_each_re_referenced_package_has_a_debug_line_naming_both_refs(monkeypatch):
    debug = _logged(monkeypatch, "debug")

    result = _merged(_numbered(12, "held"), _numbered(12, "other"))

    new_refs = {
        component.purl: component.bom_ref.root for component in result.components
    }
    for n in range(1, 13):
        assert any(
            f"'{n}'" in line and repr(new_refs[f"pkg:pypi/other{n}@1.0"]) in line
            for line in debug
        )


def test_each_merge_logs_a_warning_of_its_own(monkeypatch):
    warnings = _logged(monkeypatch, "warning")

    first = _merged(_numbered(2, "held"), _numbered(2, "other"))
    _merged(first, _numbered(2, "third"))

    assert len(warnings) == 2


def test_no_warning_is_logged_when_every_shared_ref_is_one_package(monkeypatch):
    lines: list[str] = []
    monkeypatch.setattr(
        ASH_LOGGER, "warning", lambda message, *args, **kwargs: lines.append(message)
    )
    held = _sbom([_component("1", REQUESTS)])
    incoming = _sbom([_component("1", REQUESTS), _component("2", FLASK)])

    _merged(held, incoming)

    assert lines == []
