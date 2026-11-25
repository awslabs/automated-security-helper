# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Consistency of the operational register with the production declarations.

The register (automated_security_helper/base/scanner_operational_facets.py)
mirrors, and does not replace, what ASH already declares: ``offline_strategy``,
``SandboxRequirements``, ``CONTENT_DATABASES``, ``SCANNERS_WITHOUT_CONTENT_
DATABASE``, ``tool_type`` (and the ``SCANNER_TOOL_TYPES`` table), ``covers``,
``python_only``, ``use_uv_tool``, ``external_executables``,
``success_exit_codes`` and the ``tool_downloads`` tables. Each test here binds
one mirrored field to the production declaration it names and fails, naming
the scanner, when they tell different stories. A register that only validated
its own shape could never fail; these are the rows that can.

The sweep is pure construction and static reads: scanner instances are built
with a mock context (no tool is run, no network is touched) and the fixtures
are parsed, never scanned.

Planted controls guard the enumerations: a count of 22, the exact set of
scanner names against ``SCANNER_TOOL_TYPES``, and a classifier control for
the output-format reader, because a sweep over a silently shrunken or
mis-parsed universe would pass vacuously.
"""

from __future__ import annotations

import importlib
import json
import pkgutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.plugin_modules import ash_builtin
from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

pytestmark = pytest.mark.unit

# Rebuild models to resolve forward references, as the other construction
# tests do.
AshConfig.model_rebuild()

_REMAINING_LOAD_ERRORS = ash_builtin.retry_failed_plugin_groups()

_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "test_data" / "scanners"


def _registered_scanner_classes() -> list[type]:
    classes: list[type] = []
    seen: set[type] = set()
    modules = sorted(
        pkgutil.iter_modules(plugin_modules.__path__), key=lambda m: m.name
    )
    for info in modules:
        if not info.ispkg:
            continue
        package = importlib.import_module(f"{plugin_modules.__name__}.{info.name}")
        for cls in getattr(package, "ASH_SCANNERS", []):
            if cls not in seen:
                seen.add(cls)
                classes.append(cls)
    return classes


SCANNER_CLASSES = _registered_scanner_classes()


def _ops(cls: type) -> opsf.ScannerOperationalFacets:
    declared = vars(cls).get(opsf.OPERATIONAL_FACETS_ATTR)
    assert declared is not None, f"{cls.__qualname__} declares no operational facets"
    return declared


@pytest.fixture(scope="module")
def _context(tmp_path_factory):
    root = tmp_path_factory.mktemp("opsfacets")
    ctx = MagicMock(spec=PluginContext)
    ctx.source_dir = root / "src"
    ctx.output_dir = root / "out"
    ctx.source_dir.mkdir()
    ctx.output_dir.mkdir()
    ctx.global_ignore_paths = []
    return ctx


@pytest.fixture(scope="module")
def _instances(_context) -> dict[type, ScannerPluginBase]:
    """One constructed instance per scanner class; no tool is run."""
    return {cls: cls(context=_context) for cls in SCANNER_CLASSES}


# ---------------------------------------------------------------------------
# The universe
# ---------------------------------------------------------------------------


def test_the_universe_is_the_twenty_two_shipped_scanners() -> None:
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    assert len(SCANNER_CLASSES) == 22, sorted(c.__name__ for c in SCANNER_CLASSES)
    names = [_ops(cls).scanner_name for cls in SCANNER_CLASSES]
    assert len(set(names)) == len(names), f"duplicate scanner_name in {names}"
    assert set(names) == set(SCANNER_TOOL_TYPES), (
        "the register's scanner names and utils/scanner_names.SCANNER_TOOL_TYPES "
        f"disagree: only in register {sorted(set(names) - set(SCANNER_TOOL_TYPES))}, "
        f"only in table {sorted(set(SCANNER_TOOL_TYPES) - set(names))}"
    )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_scanner_name_is_the_name_its_config_carries(cls, _instances) -> None:
    assert _ops(cls).scanner_name == _instances[cls].config.name


# ---------------------------------------------------------------------------
# A. Network behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_offline_strategy_mirrors_the_class_attribute(cls) -> None:
    network = _ops(cls).network
    assert cls.offline_strategy is not OfflineStrategy.UNKNOWN, (
        f"{cls.__qualname__}.offline_strategy is the base default UNKNOWN (E7)"
    )
    assert network.offline_strategy is cls.offline_strategy, (
        f"{cls.__qualname__}: the register says {network.offline_strategy.value}, "
        f"the class attribute says {cls.offline_strategy.value}"
    )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_sandbox_network_mirrors_the_sandbox_requirements(cls, _instances) -> None:
    requirements = _instances[cls].sandbox_requirements
    if requirements.network_requires_grant:
        derived = opsf.SandboxNetwork.VERIFYING
    elif requirements.network:
        derived = opsf.SandboxNetwork.ONLINE
    else:
        derived = opsf.SandboxNetwork.NONE
    assert _ops(cls).network.sandbox_network is derived, (
        f"{cls.__qualname__}: SandboxRequirements gives {derived.value} "
        f"(network={requirements.network}, "
        f"requires_grant={requirements.network_requires_grant})"
    )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_content_database_join_agrees_both_ways(cls) -> None:
    """The register, CONTENT_DATABASES and SCANNERS_WITHOUT_CONTENT_DATABASE
    tell one story, in both directions.

    This extends the drift gate tests/unit/utils/test_content_db_staleness.py
    keeps for CACHE_FLAGS scanners to every strategy.
    """
    facets = _ops(cls)
    name = facets.scanner_name
    network = facets.network
    owning = [entry for entry in cdb.CONTENT_DATABASES if name in entry.readers]
    if owning:
        assert len(owning) == 1, f"{name} is read by two databases: {owning}"
        assert network.content_database == owning[0].name, (
            f"{name} reads the content database {owning[0].name!r} per "
            f"utils/content_databases.py but the register says "
            f"{network.content_database!r}"
        )
    else:
        assert network.content_database is None, (
            f"the register names content database {network.content_database!r} "
            f"for {name}, which CONTENT_DATABASES does not list it as reading"
        )
    if network.content_database is not None:
        entry = cdb.get(network.content_database)
        declares_ci_cache = opsf.Prefetch.CI_CACHE in network.prefetch
        assert declares_ci_cache == entry.cacheable_in_ci, (
            f"{name}: ci_cache prefetch is {declares_ci_cache} but "
            f"{entry.name}.cacheable_in_ci is {entry.cacheable_in_ci}"
        )
    else:
        assert opsf.Prefetch.CI_CACHE not in network.prefetch
    if cls.offline_strategy is OfflineStrategy.CACHE_FLAGS and not owning:
        assert name in cdb.SCANNERS_WITHOUT_CONTENT_DATABASE, (
            f"{name} keeps an offline cache (CACHE_FLAGS) yet reads no declared "
            "content database and has no SCANNERS_WITHOUT_CONTENT_DATABASE reason"
        )
    if name in cdb.SCANNERS_WITHOUT_CONTENT_DATABASE:
        assert cls.offline_strategy is OfflineStrategy.CACHE_FLAGS and not owning


def test_the_service_upload_scanner_is_the_one_that_skips_offline() -> None:
    """E4: snyk-code uploads the source, so its row can never read as a
    ruleset fetch, and its declared offline outcome is not_run."""
    uploads = [
        _ops(c).scanner_name
        for c in SCANNER_CLASSES
        if _ops(c).network.fetch_kind is opsf.FetchKind.SERVICE_UPLOAD
    ]
    assert uploads == ["snyk-code"], uploads
    skipped = sorted(
        _ops(c).scanner_name
        for c in SCANNER_CLASSES
        if _ops(c).network.offline_outcome is opsf.OfflineOutcome.NOT_RUN
    )
    assert skipped == ["npm-audit", "snyk-code"], skipped


# ---------------------------------------------------------------------------
# B. Output types
# ---------------------------------------------------------------------------


def classify_output(document: object) -> opsf.OutputFormat:
    """Classify a parsed native output the way the register names formats."""
    if isinstance(document, dict):
        if str(document.get("bomFormat", "")).lower() == "cyclonedx":
            return opsf.OutputFormat.CYCLONEDX
        if "runs" in document and str(document.get("version", "")).startswith("2.1"):
            return opsf.OutputFormat.SARIF
    return opsf.OutputFormat.TOOL_JSON


#: scanner -> (committed raw native output, the format it must classify as).
_NATIVE_FIXTURES: dict[str, tuple[str, opsf.OutputFormat]] = {
    "bandit": ("bandit/captured/bandit-1.9.4-m0.sarif", opsf.OutputFormat.SARIF),
    "betterleaks": ("betterleaks/captured/positive.sarif", opsf.OutputFormat.SARIF),
    "gitleaks": ("gitleaks/gitleaks-8.30.1.sarif", opsf.OutputFormat.SARIF),
    "cfn-lint": (
        "cfn_lint_guard/captured/cfn-lint-1.57.1-insecure.sarif",
        opsf.OutputFormat.SARIF,
    ),
    "cfn-guard": (
        "cfn_lint_guard/captured/cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif",
        opsf.OutputFormat.SARIF,
    ),
    "hadolint": ("hadolint/captured/positive.sarif", opsf.OutputFormat.SARIF),
    "opengrep": (
        "opengrep/captured/opengrep-2.0.0-m0.sarif",
        opsf.OutputFormat.SARIF,
    ),
    "trivy": ("trivy/trivy-0.69.3.vuln.sarif", opsf.OutputFormat.SARIF),
    "trivy-repo": ("trivy/trivy-0.75.0.shared-cve.sarif", opsf.OutputFormat.SARIF),
    "zizmor": ("zizmor/zizmor-1.30.1.sarif", opsf.OutputFormat.SARIF),
    "guarddog": (
        "guarddog/captured/scan_npm_npm_suspicious.json",
        opsf.OutputFormat.TOOL_JSON,
    ),
    "actionlint": (
        "actionlint/actionlint-1.7.12-default.json",
        opsf.OutputFormat.TOOL_JSON,
    ),
    "npm-audit": ("npmaudit/npm.json", opsf.OutputFormat.TOOL_JSON),
}


def test_the_output_classifier_has_a_positive_and_a_negative_control() -> None:
    assert classify_output({"version": "2.1.0", "runs": []}) is opsf.OutputFormat.SARIF
    assert (
        classify_output({"bomFormat": "CycloneDX", "components": []})
        is opsf.OutputFormat.CYCLONEDX
    )
    assert classify_output({"results": []}) is opsf.OutputFormat.TOOL_JSON
    assert classify_output([]) is opsf.OutputFormat.TOOL_JSON


@pytest.mark.parametrize("scanner_name", sorted(_NATIVE_FIXTURES))
def test_declared_native_format_matches_the_committed_fixture(scanner_name) -> None:
    relative, expected = _NATIVE_FIXTURES[scanner_name]
    path = _FIXTURE_ROOT / relative
    assert path.is_file(), f"fixture moved or deleted: {path}"
    document = json.loads(path.read_text(encoding="utf-8"))
    actual = classify_output(document)
    assert actual is expected, (
        f"{relative} is {actual.value}, expected {expected.value}"
    )
    declared = next(
        _ops(c) for c in SCANNER_CLASSES if _ops(c).scanner_name == scanner_name
    )
    assert actual in declared.output.native_formats, (
        f"{scanner_name} declares {[f.value for f in declared.output.native_formats]} "
        f"but its committed native output is {actual.value}"
    )


# ---------------------------------------------------------------------------
# C. Scan-target types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_tool_type_is_one_story_across_four_declarations(cls, _instances) -> None:
    """The register, the scanner's own ``tool_type``, the ``SCANNER_TOOL_TYPES``
    table the reporters read, and the declared target kinds agree.

    ``tool_type`` feeds the reporter-side ``exclude_scanner_types``, so a type
    that contradicts what the scanner scans is behavior-visible (E3).
    """
    facets = _ops(cls)
    declared = facets.targets.tool_type
    assert _instances[cls].tool_type is declared, (
        f"{facets.scanner_name}: the register says {declared.value}, the scanner "
        f"sets {_instances[cls].tool_type.value}"
    )
    assert SCANNER_TOOL_TYPES[facets.scanner_name] == declared.value, (
        f"{facets.scanner_name}: utils/scanner_names.SCANNER_TOOL_TYPES says "
        f"{SCANNER_TOOL_TYPES[facets.scanner_name]}, the register {declared.value}"
    )
    served_by = opsf.TOOL_TYPE_SERVED_BY[declared]
    assert set(facets.targets.kinds) & served_by, (
        f"{facets.scanner_name} is typed {declared.value} but declares target "
        f"kinds {[k.value for k in facets.targets.kinds]}, none of which a "
        f"{declared.value} scanner scans ({sorted(k.value for k in served_by)})"
    )


def test_the_actionlint_zizmor_split_is_recorded_and_unchanged() -> None:
    """E3: same target kind, two types. Recorded, never silently moved."""
    by_name = {_ops(c).scanner_name: _ops(c) for c in SCANNER_CLASSES}
    assert by_name["actionlint"].targets.tool_type is ScannerToolType.IAC
    assert by_name["zizmor"].targets.tool_type is ScannerToolType.SAST
    for name in ("actionlint", "zizmor"):
        assert (by_name[name].targets.tool_type_note or "").strip()


def test_trivy_repo_is_sca_and_records_the_correction() -> None:
    trivy_repo = next(
        _ops(c) for c in SCANNER_CLASSES if _ops(c).scanner_name == "trivy-repo"
    )
    assert trivy_repo.targets.tool_type is ScannerToolType.SCA
    assert "SAST" in (trivy_repo.targets.tool_type_note or "")


def test_every_target_kind_is_claimed_or_unclaimed_and_never_both() -> None:
    claimed = {k for c in SCANNER_CLASSES for k in _ops(c).targets.kinds}
    assert claimed.isdisjoint(opsf.UNCLAIMED_TARGET_KINDS)
    missing = [
        k
        for k in opsf.TargetKind
        if k not in claimed and k not in opsf.UNCLAIMED_TARGET_KINDS
    ]
    assert not missing, f"target kinds nothing claims and nothing lists: {missing}"
    assert opsf.TargetKind.SECRETS_GIT_HISTORY in opsf.UNCLAIMED_TARGET_KINDS


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_covers_is_display_only_and_never_claims_what_is_not_wired(cls) -> None:
    """E10: ``covers`` is the display string; the register declares the wired
    truth, and the display string may not claim an unwired target."""
    facets = _ops(cls)
    covers = getattr(cls, "covers", None)
    if not covers:
        assert (facets.targets.covers_note or "").strip(), (
            f"{facets.scanner_name} declares no covers display string and its "
            "register row does not record that (targets.covers_note)"
        )
        return
    text = " ".join(covers).lower()
    assert "container image" not in text, (
        f"{facets.scanner_name} covers claims container images; no scanner is "
        "wired to scan one (UNCLAIMED_TARGET_KINDS)"
    )
    assert "git history" not in text
    if opsf.TargetKind.IAC_OTHER in facets.targets.kinds:
        assert "other" in text, (
            f"{facets.scanner_name} scans other IaC frameworks but its covers "
            f"display string {covers} names none"
        )


# ---------------------------------------------------------------------------
# F / G. Runtime and platforms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_runtime_mirrors_the_class_and_instance_declarations(cls, _instances) -> None:
    facets = _ops(cls)
    runtime = facets.runtime
    instance = _instances[cls]
    assert runtime.use_uv_tool is bool(instance.use_uv_tool), (
        f"{facets.scanner_name}: use_uv_tool is {instance.use_uv_tool} at construction"
    )
    assert runtime.python_only is bool(instance.is_python_only()), (
        f"{facets.scanner_name}: is_python_only() is {instance.is_python_only()}"
    )
    for program in getattr(cls, "external_executables", ()):
        assert program in runtime.external_programs, (
            f"{facets.scanner_name}: external_executables names {program!r}, "
            "the register's external_programs does not"
        )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_platforms_are_derived_from_the_download_table(cls) -> None:
    facets = _ops(cls)
    runtime, platforms = facets.runtime, facets.platforms
    if runtime.kind is opsf.RuntimeKind.PINNED_BINARY:
        key = runtime.tool_versions_key
        assert key in tool_downloads.TOOL_VERSIONS, (
            f"{facets.scanner_name} names TOOL_VERSIONS key {key!r}, which is not pinned"
        )
        derived = tuple(
            f"{os}/{arch}" for os, arch in tool_downloads.supported_platforms(key)
        )
        assert platforms.provisionable == derived, (
            f"{facets.scanner_name}: the register says {platforms.provisionable}, "
            f"tool_downloads.supported_platforms({key!r}) says {derived}"
        )
    else:
        assert platforms.provisionable == (), (
            f"{facets.scanner_name} is not a pinned binary, so ASH provisions "
            "nothing for it and the register declares no platforms"
        )


def test_every_pinned_binary_is_claimed_by_a_scanner() -> None:
    """A pin in TOOL_VERSIONS with no register row is a scanner binary the
    register cannot see (uv is the installer, not a scanner)."""
    claimed = {
        _ops(c).runtime.tool_versions_key
        for c in SCANNER_CLASSES
        if _ops(c).runtime.tool_versions_key
    }
    unclaimed = set(tool_downloads.TOOL_VERSIONS) - claimed - {"uv"}
    assert not unclaimed, f"pinned tools no scanner row names: {sorted(unclaimed)}"


def test_the_ruby_gem_row_states_the_portable_ruby_build_dependency() -> None:
    gems = [
        c for c in SCANNER_CLASSES if _ops(c).runtime.kind is opsf.RuntimeKind.RUBY_GEM
    ]
    assert [_ops(c).scanner_name for c in gems] == ["cfn-nag"]
    dependency = (_ops(gems[0]).runtime.build_dependency or "").lower()
    assert "portable" in dependency and "build" in dependency
    assert "not a ruby version" in dependency


# ---------------------------------------------------------------------------
# H. Severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_a_scanner_with_no_findings_has_no_severity_facet(cls) -> None:
    facets = _ops(cls)
    severity_cell = vars(cls)[SCANNER_FACETS_ATTR].severity
    if facets.severity.severity_class is opsf.SeverityClass.NOT_APPLICABLE:
        assert severity_cell.state is FacetState.NA
    # The converse is not asserted: the mapping register may declare severity
    # n/a for a scanner whose native severity was never read (checkov's sample
    # run is owed), while this register still records the class ASH applies.


# ---------------------------------------------------------------------------
# K. Extensibility / L. Exit codes / M. Provenance / N. Prerequisites
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_env_prefixes_mirror_the_sandbox_requirements(cls, _instances) -> None:
    requirements = _instances[cls].sandbox_requirements
    assert _ops(cls).extensibility.env_prefixes == tuple(requirements.env_prefixes)


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_success_exit_codes_mirror_the_class_attribute(cls) -> None:
    assert _ops(cls).exit_codes.success_exit_codes == tuple(
        sorted(cls.success_exit_codes)
    )


_SOURCE_FOR_RUNTIME = {
    opsf.RuntimeKind.PINNED_BINARY: {opsf.ProvenanceSource.PINNED_RELEASE_BINARY},
    opsf.RuntimeKind.UV_PYTHON: {opsf.ProvenanceSource.PYPI_VIA_UV},
    opsf.RuntimeKind.RUBY_GEM: {opsf.ProvenanceSource.GEMFILE_LOCK},
    opsf.RuntimeKind.NODE_SUBCOMMAND: {opsf.ProvenanceSource.USER_INSTALLED},
    opsf.RuntimeKind.USER_INSTALLED_CLI: {opsf.ProvenanceSource.USER_INSTALLED},
    opsf.RuntimeKind.IN_PROCESS: {opsf.ProvenanceSource.PYPI_PINNED_DEPENDENCY},
    opsf.RuntimeKind.PYPI_PACKAGE: {opsf.ProvenanceSource.PYPI_PINNED_DEPENDENCY},
}


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_provenance_agrees_with_the_runtime_and_declares_no_tier(cls) -> None:
    facets = _ops(cls)
    assert facets.provenance.source in _SOURCE_FOR_RUNTIME[facets.runtime.kind], (
        f"{facets.scanner_name}: a {facets.runtime.kind.value} runtime cannot "
        f"have provenance {facets.provenance.source.value}"
    )
    # A scanner's maturity tier is registry membership, declared once in the
    # member lists: an in-tree scanner that declares the deprecated per-plugin
    # field is re-growing the parallel carrier the registries deleted.
    assert facets.provenance.tier is None, (
        f"{cls.__module__} declares tier={facets.provenance.tier!r}; the tier "
        "is registry membership (plugins.registries), never a per-scanner "
        "declaration"
    )
    # And every in-tree scanner's module is a member of a shipped registry,
    # read uniformly (which one is not this test's business).
    from automated_security_helper.plugins.registries import registry_of

    assert registry_of(cls.__module__) is not None, (
        f"{cls.__module__} is in no shipped registry's member list"
    )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_prerequisites_agree_with_the_scanners_own_selection(cls, _instances) -> None:
    facets = _ops(cls)
    kinds = set(facets.prerequisites.kinds)
    if kinds & {opsf.Prerequisite.LOCKFILE, opsf.Prerequisite.TEMPLATE}:
        assert (
            cls.nothing_to_scan_reason is not ScannerPluginBase.nothing_to_scan_reason
        ), (
            f"{facets.scanner_name} declares a {sorted(k.value for k in kinds)} "
            "prerequisite but does not override nothing_to_scan_reason, so an "
            "absent tool on a tree without it reads MISSING, not SKIPPED"
        )
    if opsf.Prerequisite.NODE_RUNTIME in kinds:
        assert "node" in facets.runtime.external_programs
    if opsf.Prerequisite.AUTH_TOKEN in kinds:
        requirements = _instances[cls].sandbox_requirements
        assert requirements.env_names or requirements.read_paths, (
            f"{facets.scanner_name} needs a token but its sandbox declaration "
            "passes neither an env name nor a token file"
        )
