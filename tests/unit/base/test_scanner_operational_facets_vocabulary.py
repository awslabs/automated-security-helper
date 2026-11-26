# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Vocabulary totality and fail-closed construction of the operational register.

``ScannerOperationalFacets.model_fields`` must equal ``OPERATIONAL_FACET_NAMES``
exactly and in order, every field required, so the tuple docs generation reads
and the model scanners declare against cannot drift apart (the same meta-test
the mapping register has, tests/unit/base/test_scanner_facets_vocabulary.py).

The rest of the module is the must-NOT half of each sub-model's validation: a
declaration that contradicts itself or carries a state without its evidence is
refused at construction, so an unevidenced operational claim cannot enter the
register. Each refusal row builds a valid control first and mutates one field,
so a passing refusal is the validator firing, not a malformed fixture.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType

pytestmark = pytest.mark.unit


def test_model_fields_are_exactly_the_vocabulary_in_order() -> None:
    assert tuple(opsf.ScannerOperationalFacets.model_fields) == (
        opsf.OPERATIONAL_FACET_NAMES
    )


def test_every_field_is_required() -> None:
    for name, field in opsf.ScannerOperationalFacets.model_fields.items():
        assert field.is_required(), f"operational facet {name!r} must be required"


def test_unknown_fields_are_refused() -> None:
    with pytest.raises(ValidationError):
        opsf.NetworkFacet(**{**_network_kwargs(), "invented": 1})


# ---- valid controls -------------------------------------------------------


def _network_kwargs() -> dict:
    return {
        "fetch_kind": opsf.FetchKind.NONE,
        "fetches": (),
        "prefetch": (),
        "offline_outcome": opsf.OfflineOutcome.UNCHANGED,
        "offline_strategy": OfflineStrategy.BUNDLED,
        "sandbox_network": opsf.SandboxNetwork.NONE,
        "source": "a source",
    }


def _fetching_kwargs() -> dict:
    return {
        **_network_kwargs(),
        "fetch_kind": opsf.FetchKind.CONTENT_FETCH,
        "fetches": (opsf.Fetched.VULN_DB,),
        "offline_outcome": opsf.OfflineOutcome.DEGRADED,
        "offline_reason": "runs from the cache",
        "offline_strategy": OfflineStrategy.CACHE_FLAGS,
        "sandbox_network": opsf.SandboxNetwork.ONLINE,
    }


def test_the_controls_construct() -> None:
    opsf.NetworkFacet(**_network_kwargs())
    opsf.NetworkFacet(**_fetching_kwargs())


# ---- network refusals -----------------------------------------------------


@pytest.mark.parametrize(
    ("label", "base", "change"),
    [
        (
            "UNKNOWN offline_strategy is the enum's honest-ignorance value",
            _network_kwargs,
            {"offline_strategy": OfflineStrategy.UNKNOWN},
        ),
        (
            "content_fetch must name what it fetches",
            _fetching_kwargs,
            {"fetches": ()},
        ),
        (
            "a none fetch_kind cannot name artifacts",
            _network_kwargs,
            {"fetches": (opsf.Fetched.VULN_DB,)},
        ),
        (
            "source_upload requires service_upload",
            _fetching_kwargs,
            {"fetches": (opsf.Fetched.SOURCE_UPLOAD,)},
        ),
        (
            "a degraded outcome needs a reason",
            _fetching_kwargs,
            {"offline_reason": None},
        ),
        (
            "not_run contradicts a bundled strategy",
            _network_kwargs,
            {
                "offline_outcome": opsf.OfflineOutcome.NOT_RUN,
                "offline_reason": "skipped",
            },
        ),
        (
            "skip_offline requires the not_run outcome",
            _network_kwargs,
            {"offline_strategy": OfflineStrategy.SKIP_OFFLINE},
        ),
        (
            "a sandbox network grant needs a fetch that uses it",
            _network_kwargs,
            {"sandbox_network": opsf.SandboxNetwork.ONLINE},
        ),
        (
            "content_fetch with no sandbox network must say what differs",
            _fetching_kwargs,
            {"sandbox_network": opsf.SandboxNetwork.NONE},
        ),
        (
            "a content database means content_fetch",
            _network_kwargs,
            {"content_database": "grype-db"},
        ),
        (
            "a CI cache needs the database it caches",
            _fetching_kwargs,
            {"prefetch": (opsf.Prefetch.CI_CACHE,)},
        ),
        (
            "a network row cites its source",
            _network_kwargs,
            {"source": " "},
        ),
    ],
)
def test_network_refusals(label: str, base, change: dict) -> None:
    with pytest.raises(ValidationError):
        opsf.NetworkFacet(**{**base(), **change})


def test_service_upload_requires_source_upload_and_not_run_pairs() -> None:
    upload = {
        **_fetching_kwargs(),
        "fetch_kind": opsf.FetchKind.SERVICE_UPLOAD,
        "fetches": (opsf.Fetched.SOURCE_UPLOAD,),
        "offline_outcome": opsf.OfflineOutcome.NOT_RUN,
        "offline_strategy": OfflineStrategy.SKIP_OFFLINE,
    }
    opsf.NetworkFacet(**upload)
    with pytest.raises(ValidationError):
        opsf.NetworkFacet(**{**upload, "fetches": (opsf.Fetched.VULN_DB,)})


# ---- targets --------------------------------------------------------------


def test_targets_refuse_a_kind_no_scanner_is_wired_for() -> None:
    for kind in opsf.UNCLAIMED_TARGET_KINDS:
        with pytest.raises(ValidationError):
            opsf.TargetsFacet(
                kinds=(kind,),
                tool_type=ScannerToolType.SECRETS,
                selection="a mechanism",
            )


def test_targets_need_a_kind_and_a_selection() -> None:
    with pytest.raises(ValidationError):
        opsf.TargetsFacet(
            kinds=(), tool_type=ScannerToolType.SAST, selection="a mechanism"
        )
    with pytest.raises(ValidationError):
        opsf.TargetsFacet(
            kinds=(opsf.TargetKind.SOURCE_CODE,),
            tool_type=ScannerToolType.SAST,
            selection="",
        )


def test_every_target_kind_is_served_or_unclaimed_by_a_tool_type() -> None:
    """The tool-type table and the unclaimed table must leave no kind orphaned
    in the vocabulary: a new kind that nothing serves is a decision, not a
    default."""
    served = set().union(*opsf.TOOL_TYPE_SERVED_BY.values())
    orphaned = [
        k
        for k in opsf.TargetKind
        if k not in served and k not in opsf.UNCLAIMED_TARGET_KINDS
    ]
    assert not orphaned, f"target kinds served by no tool type: {orphaned}"


def test_a_container_scanner_is_served_by_a_container_image() -> None:
    """dockle lints one image, so the CONTAINER tool type has a served kind: the
    container_image kind alone, which a CONTAINER row can claim."""
    assert opsf.TargetKind.CONTAINER_IMAGE not in opsf.UNCLAIMED_TARGET_KINDS
    assert opsf.TOOL_TYPE_SERVED_BY[ScannerToolType.CONTAINER] == frozenset(
        {opsf.TargetKind.CONTAINER_IMAGE}
    )
    row = opsf.TargetsFacet(
        kinds=(opsf.TargetKind.CONTAINER_IMAGE,),
        tool_type=ScannerToolType.CONTAINER,
        selection="an image reference, or a saved image handed to --input",
    )
    assert row.kinds == (opsf.TargetKind.CONTAINER_IMAGE,)


# ---- runtime --------------------------------------------------------------


def _runtime(**change) -> opsf.RuntimeFacet:
    base = {
        "kind": opsf.RuntimeKind.IN_PROCESS,
        "external_programs": (),
        "invocations": opsf.Invocations.ONE,
        "python_only": True,
        "use_uv_tool": False,
    }
    return opsf.RuntimeFacet(**{**base, **change})


def test_runtime_refusals() -> None:
    _runtime()
    with pytest.raises(ValidationError):
        _runtime(kind=opsf.RuntimeKind.PINNED_BINARY)  # no key
    with pytest.raises(ValidationError):
        _runtime(tool_versions_key="grype")  # key on a non-pinned kind
    with pytest.raises(ValidationError):
        _runtime(kind=opsf.RuntimeKind.RUBY_GEM)  # no build dependency
    with pytest.raises(ValidationError):
        _runtime(kind=opsf.RuntimeKind.UV_PYTHON)  # uv kind without use_uv_tool
    with pytest.raises(ValidationError):
        _runtime(use_uv_tool=True)  # use_uv_tool on a non-uv kind
    with pytest.raises(ValidationError):
        _runtime(invocations=opsf.Invocations.PER_TARGET)  # no note
    _runtime(kind=opsf.RuntimeKind.PINNED_BINARY, tool_versions_key="grype")
    _runtime(kind=opsf.RuntimeKind.RUBY_GEM, build_dependency="a portable build")


# ---- severity, silencing, identity, exit codes, provenance, prerequisites --


def test_severity_degraded_names_the_dropped_field_and_only_degraded_does() -> None:
    opsf.SeverityFacet(
        severity_class=opsf.SeverityClass.DEGRADED,
        note="n",
        dropped_native="priorityScore",
    )
    with pytest.raises(ValidationError):
        opsf.SeverityFacet(severity_class=opsf.SeverityClass.DEGRADED, note="n")
    with pytest.raises(ValidationError):
        opsf.SeverityFacet(
            severity_class=opsf.SeverityClass.NATIVE,
            note="n",
            dropped_native="priorityScore",
        )


def test_silencing_refusals() -> None:
    layer = {
        "layer": opsf.SilencingLayerKind.INLINE_COMMENT,
        "writer": opsf.SilencingWriter.REPOSITORY,
        "honored": opsf.Honored.YES,
        "surface": "a surface",
        "cite": "a citation",
    }
    opsf.SilencingLayer(**layer)
    with pytest.raises(ValidationError):
        opsf.SilencingLayer(**{**layer, "honored": opsf.Honored.UNCONFIRMED})
    with pytest.raises(ValidationError):
        opsf.SilencingLayer(**{**layer, "cite": ""})
    with pytest.raises(ValidationError):
        opsf.SilencingFacet(tool_side=())
    opsf.SilencingFacet(tool_side=(), none_reason="there is nothing to silence")


def test_exit_codes_are_sorted_unique_and_non_empty() -> None:
    opsf.ExitCodesFacet(success_exit_codes=(0, 1), semantics="s")
    for bad in ((), (1, 0), (0, 0)):
        with pytest.raises(ValidationError):
            opsf.ExitCodesFacet(success_exit_codes=bad, semantics="s")


def test_an_upstream_license_is_not_read_or_cited_never_recalled() -> None:
    base = {
        "source": opsf.ProvenanceSource.PYPI_VIA_UV,
        "selection_surfaces": (),
    }
    opsf.ProvenanceFacet(**base, upstream_license=opsf.LICENSE_NOT_READ)
    opsf.ProvenanceFacet(
        **base, upstream_license="Apache-2.0 (source: the pinned upstream LICENSE)"
    )
    with pytest.raises(ValidationError):
        opsf.ProvenanceFacet(**base, upstream_license="Apache-2.0")


def test_prerequisites_refusals() -> None:
    opsf.PrerequisitesFacet(kinds=(opsf.Prerequisite.NONE,), note="n")
    with pytest.raises(ValidationError):
        opsf.PrerequisitesFacet(kinds=(), note="n")
    with pytest.raises(ValidationError):
        opsf.PrerequisitesFacet(
            kinds=(opsf.Prerequisite.NONE, opsf.Prerequisite.LOCKFILE), note="n"
        )


def test_a_built_declaration_cannot_be_mutated() -> None:
    facet = opsf.PrerequisitesFacet(kinds=(opsf.Prerequisite.NONE,), note="n")
    with pytest.raises(ValidationError):
        facet.note = "changed"  # type: ignore[misc]


def test_the_platform_constants_are_the_published_orders() -> None:
    assert opsf.PLATFORMS_NO_WINDOWS_ARM64 == opsf.PLATFORMS_ALL[:-1]
    assert list(opsf.PLATFORMS_ALL) == sorted(opsf.PLATFORMS_ALL)
