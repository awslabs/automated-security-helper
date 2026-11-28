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

from typing import Any

import pytest
from pydantic import ValidationError

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.core import enums
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


def test_every_target_kind_is_served_or_unclaimed_by_a_category() -> None:
    """The category table and the unclaimed table must leave no kind orphaned
    in the vocabulary: a new kind that nothing serves is a decision, not a
    default."""
    served_by = getattr(opsf, "CATEGORY_SERVED_BY", None)
    assert served_by is not None, (
        "base/scanner_operational_facets.py has no CATEGORY_SERVED_BY"
    )
    served = set().union(*served_by.values())
    orphaned = [
        k
        for k in opsf.TargetKind
        if k not in served and k not in opsf.UNCLAIMED_TARGET_KINDS
    ]
    assert not orphaned, f"target kinds served by no category: {orphaned}"


# ---- targets: categories --------------------------------------------------

#: Each tool type, by member name, and the value of the category a row of that
#: type derives when it writes no categories.
_DERIVED_CATEGORY: tuple[tuple[str, str | None], ...] = (
    ("SAST", "sast"),
    ("DAST", "dast"),
    ("SCA", "sca"),
    ("IAC", "iac"),
    ("SECRETS", "secrets"),
    ("CONTAINER", "container"),
    ("SBOM", "sbom"),
    ("CUSTOM", "other"),
    ("UNKNOWN", None),
)


def _categories_are_declared() -> None:
    assert "categories" in opsf.TargetsFacet.model_fields, (
        "TargetsFacet declares no categories field"
    )


def _scan_category() -> Any:
    """``core.enums.ScanCategory``, read when the test runs rather than at import."""
    found = getattr(enums, "ScanCategory", None)
    assert found is not None, "core.enums has no ScanCategory"
    return found


def _targets(**change: Any) -> opsf.TargetsFacet:
    """A targets row of one source-code kind, typed SAST, with *change* applied."""
    row: dict[str, Any] = {
        "kinds": (opsf.TargetKind.SOURCE_CODE,),
        "tool_type": ScannerToolType.SAST,
        "selection": "a mechanism",
    }
    row.update(change)
    return opsf.TargetsFacet(**row)


def test_the_category_fields_follow_their_tool_type_fields() -> None:
    """``categories`` follows ``tool_type`` and ``categories_note`` follows
    ``tool_type_note``, so a row reads as the legacy field, then what replaces
    it."""
    fields = list(opsf.TargetsFacet.model_fields)

    for field, after in (
        ("categories", "tool_type"),
        ("categories_note", "tool_type_note"),
    ):
        assert field in fields, f"TargetsFacet declares no {field} field"
        assert fields.index(field) == fields.index(after) + 1, fields


@pytest.mark.parametrize(
    ("tool_type", "value"),
    _DERIVED_CATEGORY,
    ids=[name for name, _ in _DERIVED_CATEGORY],
)
def test_a_row_without_categories_derives_them_from_its_tool_type(
    tool_type: str, value: str | None
) -> None:
    _categories_are_declared()
    category = _scan_category()
    expected = () if value is None else (category(value),)

    targets = _targets(tool_type=ScannerToolType[tool_type])

    assert isinstance(targets.categories, tuple)
    assert targets.categories == expected
    assert "categories" not in targets.model_fields_set


def test_a_row_writes_its_categories_as_members_or_as_values() -> None:
    _categories_are_declared()
    category = _scan_category()

    for written in (("sast", "secrets"), (category.SAST, category.SECRETS)):
        targets = _targets(categories=written)

        assert targets.categories == (category.SAST, category.SECRETS), written
        assert all(isinstance(member, category) for member in targets.categories)
        assert "categories" in targets.model_fields_set


@pytest.mark.parametrize(
    ("categories", "refusal"),
    [
        pytest.param((), "categories is empty: name at least one category", id="empty"),
        pytest.param(
            ("sast", "sast"), "categories names sast more than once", id="repeated"
        ),
        pytest.param(
            ("secrets", "sast"),
            "categories are not in canonical order: write sast, secrets",
            id="out-of-order",
        ),
        pytest.param(
            ("ci", "sast", "iac"),
            "categories are not in canonical order: write sast, iac, ci",
            id="out-of-order-three",
        ),
    ],
)
def test_a_row_that_writes_its_categories_wrongly_is_refused(
    categories: tuple[str, ...], refusal: str
) -> None:
    _categories_are_declared()

    with pytest.raises(ValidationError) as excinfo:
        _targets(categories=categories)

    assert refusal in str(excinfo.value), str(excinfo.value)


def test_a_row_may_carry_a_categories_note() -> None:
    assert "categories_note" in opsf.TargetsFacet.model_fields, (
        "TargetsFacet declares no categories_note field"
    )
    note = "api findings are read from the OpenAPI documents it scans"

    assert _targets(categories_note=note).categories_note == note
    assert _targets().categories_note is None


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
