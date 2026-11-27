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

Planted controls guard the enumerations: a count of 23, the exact set of
scanner names against ``SCANNER_TOOL_TYPES``, and a classifier control for
the output-format reader, because a sweep over a silently shrunken or
mis-parsed universe would pass vacuously.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_facets import (
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES
from tests.unit.base.test_image_register import dockerfile_stages
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

# Rebuild models to resolve forward references, as the other construction
# tests do.
AshConfig.model_rebuild()

SCANNER_CLASSES, _REMAINING_LOAD_ERRORS = load_scanner_universe()

_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "test_data" / "scanners"


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


def test_the_universe_is_the_twenty_three_shipped_scanners() -> None:
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    assert len(SCANNER_CLASSES) == 23, sorted(c.__name__ for c in SCANNER_CLASSES)
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
    register cannot see (uv is the installer, not a scanner; crane is the registry
    client the scan phase asks for an image tag's digest, utils/image_digest_resolver.py,
    and the grype and trivy rows declare the registry read it makes)."""
    claimed = {
        _ops(c).runtime.tool_versions_key
        for c in SCANNER_CLASSES
        if _ops(c).runtime.tool_versions_key
    }
    unclaimed = set(tool_downloads.TOOL_VERSIONS) - claimed - {"uv", "crane"}
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
def test_provenance_agrees_with_the_runtime(cls) -> None:
    """The tier is the manifest's (tests/unit/plugin_manifests binds it to the
    package); the provenance source must still fit the runtime kind."""
    facets = _ops(cls)
    assert facets.provenance.source in _SOURCE_FOR_RUNTIME[facets.runtime.kind], (
        f"{facets.scanner_name}: a {facets.runtime.kind.value} runtime cannot "
        f"have provenance {facets.provenance.source.value}"
    )


# ---------------------------------------------------------------------------
# F2. Runtime compatibility rows
# ---------------------------------------------------------------------------

_RUNTIME_FOR_COMPAT = {
    opsf.RuntimeName.PYTHON: {
        opsf.RuntimeKind.UV_PYTHON,
        opsf.RuntimeKind.PYPI_PACKAGE,
    },
}


def test_the_compat_sweep_is_not_vacuous() -> None:
    """The two scanners whose per-scanner constants became rows carry them."""
    with_rows = {
        _ops(cls).scanner_name
        for cls in SCANNER_CLASSES
        if _ops(cls).runtime_compat.rows
    }
    assert {"checkov", "guarddog"} <= with_rows, with_rows


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_a_compat_row_fits_the_scanners_runtime(cls) -> None:
    facets = _ops(cls)
    for row in facets.runtime_compat.rows:
        assert facets.runtime.kind in _RUNTIME_FOR_COMPAT[row.runtime], (
            f"{facets.scanner_name}: a {row.runtime.value} compatibility row on "
            f"a {facets.runtime.kind.value} runtime constrains an interpreter "
            "ASH does not choose"
        )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_the_derived_interpreter_request_equals_the_rows(cls, _instances) -> None:
    """The register row is the source and the installer derives from it, so
    there is no per-scanner constant left to mirror."""
    instance = _instances[cls]
    facets = _ops(cls)
    expected = facets.runtime_compat.pin_request(
        opsf.RuntimeName.PYTHON, instance._get_tool_version_constraint()
    )
    assert instance._get_tool_python_request() == expected, facets.scanner_name


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_no_scanner_overrides_the_interpreter_request(cls) -> None:
    assert "_get_tool_python_request" not in vars(cls), (
        f"{cls.__name__} overrides _get_tool_python_request; declare a "
        "runtime_compat row instead"
    )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_an_open_ended_row_still_covers_the_default_tool_constraint(
    cls, _instances
) -> None:
    """The re-check at a tool bump. An open-ended row records an UNSOLVED
    upstream issue and the default tool constraint it was written against;
    when the live default moves (the bump that follows an upstream fix) this
    goes red, which is the prompt to read the row's upstream issue (or
    recheck_note) and close or re-bound the row. The equality is what makes
    the gate able to fire at all for the shipped shape -- a blank tool range
    and a range default constraint -- where ``applies_to`` alone can never go
    red; ``test_the_recheck_fires_when_the_default_constraint_moves`` proves
    the red case at the same predicate this gate calls."""
    instance = _instances[cls]
    constraint = instance._get_tool_version_constraint()
    for row in _ops(cls).runtime_compat.rows:
        if row.open_ended:
            where = row.upstream_issue or row.recheck_note
            assert not row.recheck_fires(constraint), (
                f"{_ops(cls).scanner_name}: the default tool constraint moved "
                f"from the recorded {row.recorded_default_constraint!r} to "
                f"{constraint!r}; the tool bumped, so re-read the open-ended "
                f"row ({where}) and close or re-bound it, then re-record the "
                "constraint"
            )
            assert row.applies_to(constraint), (
                f"{_ops(cls).scanner_name}: the default tool constraint "
                f"{constraint!r} is outside the open-ended row's tool range "
                f"{row.tool_versions!r}; has {where} been fixed?"
            )


def test_the_gate_reds_on_a_simulated_default_bump(_instances, monkeypatch) -> None:
    """The committed witness that the LIVE gate above can fire, not only its
    predicate (``test_the_recheck_fires_when_the_default_constraint_moves``
    proves ``recheck_fires`` on a fixture row): bump one shipped scanner's
    default tool constraint and the gate reds, naming the recorded and live
    constraints in its message."""
    with_open_ended = [
        cls
        for cls in SCANNER_CLASSES
        if any(row.open_ended for row in _ops(cls).runtime_compat.rows)
    ]
    assert with_open_ended, "no shipped open-ended row: the control has no subject"
    cls = with_open_ended[0]
    row = next(r for r in _ops(cls).runtime_compat.rows if r.open_ended)
    bumped = "==999.0.0"
    assert bumped != (row.recorded_default_constraint or "")
    monkeypatch.setattr(_instances[cls], "_get_tool_version_constraint", lambda: bumped)
    with pytest.raises(AssertionError) as excinfo:
        test_an_open_ended_row_still_covers_the_default_tool_constraint(cls, _instances)
    message = str(excinfo.value)
    assert repr(row.recorded_default_constraint) in message
    assert repr(bumped) in message


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_at_most_one_polyfill_row_applies_and_its_shim_ships(cls, _instances) -> None:
    """Python imports one ``sitecustomize``, so a second applicable polyfill
    row would silently lose to the first."""
    from automated_security_helper.utils.runtime_compat_env import (
        polyfill_directory,
    )

    facets = _ops(cls)
    constraint = _instances[cls]._get_tool_version_constraint()
    applicable = facets.runtime_compat.polyfills(constraint)
    assert len(applicable) <= 1, facets.scanner_name
    for row in facets.runtime_compat.rows:
        if row.polyfill:
            assert (polyfill_directory(row.polyfill) / "sitecustomize.py").is_file()


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_a_polyfill_row_is_never_the_default_where_a_pin_serves(cls) -> None:
    """Prefer PIN: a scanner that carries a PIN row for a tool range does not
    also carry a POLYFILL row for the same upstream issue."""
    rows = _ops(cls).runtime_compat.rows
    pinned = {r.upstream_issue for r in rows if r.resolution.value == "pin"}
    for row in rows:
        if row.resolution.value == "polyfill" and row.upstream_issue:
            assert row.upstream_issue not in pinned, (
                f"{_ops(cls).scanner_name}: {row.upstream_issue} is resolved by "
                "both a PIN and a POLYFILL row; the PIN is the preferred "
                "resolution, so the polyfill row has no reason to exist"
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


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_a_container_image_claim_and_the_image_dispatch_travel_together(cls) -> None:
    """The C5 iff-rule: claims CONTAINER_IMAGE ⇔ overrides the image dispatch.

    The register row is the one place capability lives, and the dispatch
    (``_execute_image_scan`` for a template scanner, a whole ``scan_image``
    override for a bespoke one such as syft) is the wiring the claim promises.
    A claim without the wiring would hand a scanner an image it cannot scan,
    which the base hook reports as ASH's own drift; wiring without the claim
    would be dead code the routing never reaches. Read from the class's own
    ``vars()``, as every register reading is, so an inherited override never
    answers for a subclass.
    """
    claims = opsf.TargetKind.CONTAINER_IMAGE in _ops(cls).targets.kinds
    wires = "_execute_image_scan" in vars(cls) or "scan_image" in vars(cls)
    assert claims == wires, (
        f"{_ops(cls).scanner_name}: claims container_image={claims} but "
        f"overrides the image dispatch={wires}; the register row and the "
        "wiring must travel together"
    )


def test_the_wired_image_scanners_are_grype_syft_and_trivy() -> None:
    """The first wave by name, so an accidental claim is a red row, not a drift."""
    wired = sorted(
        _ops(cls).scanner_name
        for cls in SCANNER_CLASSES
        if opsf.TargetKind.CONTAINER_IMAGE in _ops(cls).targets.kinds
    )
    assert wired == ["grype", "syft", "trivy"]


# ---------------------------------------------------------------------------
# G2. Container image route
# ---------------------------------------------------------------------------
#
# How each scanner's tool gets into the image the Dockerfile builds. The seeds were read
# from the Dockerfile, and these rows read it back: a route, a version check or a note
# that no longer matches it is a red row here, and not a surprise in a later build.
# Every name the row adds is read inside a test body, so the rows above keep running
# where the vocabulary does not exist.

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DOCKERFILE_TEXT = (_REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
_DOCKERFILE_LINES = _DOCKERFILE_TEXT.splitlines()

#: scanner -> the route value its row declares, from the Dockerfile.
_IMAGE_ROUTES = {
    "actionlint": "release_asset",
    "bandit": "dependencies_install",
    "betterleaks": "release_asset",
    "cdk-nag": "ash_wheel",
    "cfn-guard": "release_asset",
    "cfn-lint": "dependencies_install",
    "cfn-nag": "gem_bundle",
    "checkov": "dependencies_install",
    "detect-secrets": "ash_wheel",
    "ferret-scan": "not_in_image",
    "gitleaks": "release_asset",
    "grype": "release_asset",
    "guarddog": "dependencies_install",
    "hadolint": "release_asset",
    "mcp-config": "ash_wheel",
    "npm-audit": "ash_wheel",
    "opengrep": "dependencies_install",
    "semgrep": "dependencies_install",
    "snyk-code": "not_in_image",
    "syft": "release_asset",
    "trivy": "release_asset",
    "trivy-repo": "shared_tool",
    "zizmor": "dependencies_install",
}

#: Words that mark a comment as being about licensing.
_LICENSING = re.compile(
    r"licen[sc]|copyleft|\bgpl\b|\bmit\b|spdx|\bnotices?\b", re.IGNORECASE
)


def _ir():
    return importlib.import_module("automated_security_helper.base.image_register")


def _class_named(name: str) -> type:
    return next(cls for cls in SCANNER_CLASSES if _ops(cls).scanner_name == name)


def _tools_other_rows_install(name: str) -> frozenset[str]:
    """The tools the release-asset rows of every OTHER scanner install."""
    return frozenset(
        _ops(cls).image.tool
        for cls in SCANNER_CLASSES
        if _ops(cls).scanner_name != name
        and _ops(cls).image.route is opsf.ImageRoute.RELEASE_ASSET
    )


def _system_package_keys() -> frozenset[str]:
    return frozenset(package.key for package in _ir().SYSTEM_PACKAGES)


def image_route_problems(
    facets: opsf.ScannerOperationalFacets,
    installed_by_other_rows: frozenset[str],
    system_package_keys: frozenset[str],
) -> list[str]:
    """What a scanner's runtime says against the route its image row declares.

    Shared by the sweep over the shipped scanners and by the planted rows, so a row
    that passes the sweep is held to the same rule the planted rows are refused by.
    """
    image, runtime = facets.image, facets.runtime
    problems: list[str] = []
    if image.route is opsf.ImageRoute.RELEASE_ASSET:
        if runtime.kind is not opsf.RuntimeKind.PINNED_BINARY:
            problems.append(
                "a release asset needs a pinned-binary runtime, not "
                f"{runtime.kind.value}"
            )
        if image.tool != runtime.tool_versions_key:
            problems.append(
                f"the release asset {image.tool!r} is not the runtime's "
                f"TOOL_VERSIONS key {runtime.tool_versions_key!r}"
            )
        if image.tool not in tool_downloads.TOOL_VERSIONS:
            problems.append(f"{image.tool!r} is not pinned in TOOL_VERSIONS")
        if image.tool not in tool_downloads.downloadable_tools():
            problems.append(f"{image.tool!r} has no release-asset download table")
    elif image.route is opsf.ImageRoute.SHARED_TOOL:
        if image.tool not in installed_by_other_rows:
            problems.append(f"no other scanner's row installs {image.tool!r}")
        if image.tool != runtime.tool_versions_key:
            problems.append(
                f"the scanner runs {runtime.tool_versions_key!r}, not {image.tool!r}"
            )
    elif image.route is opsf.ImageRoute.GEM_BUNDLE:
        if runtime.kind is not opsf.RuntimeKind.RUBY_GEM:
            problems.append(
                f"a gem bundle needs a Ruby gem runtime, not {runtime.kind.value}"
            )
    elif image.route is opsf.ImageRoute.ASH_WHEEL:
        if runtime.kind not in (
            opsf.RuntimeKind.IN_PROCESS,
            opsf.RuntimeKind.NODE_SUBCOMMAND,
        ):
            problems.append(
                "an ASH wheel needs an in-process or node-subcommand runtime, not "
                f"{runtime.kind.value}"
            )
    elif image.route is opsf.ImageRoute.OS_PACKAGE:
        if image.package not in system_package_keys:
            problems.append(
                f"the image register names no system package {image.package!r}"
            )
    return problems


def _planted(name: str, **image) -> opsf.ScannerOperationalFacets:
    """The register row of scanner *name* with its image row replaced."""
    facets = _ops(_class_named(name))
    return facets.model_copy(update={"image": opsf.ImageFacet(**image)})


def _planted_pinned(name: str, tool: str) -> opsf.ScannerOperationalFacets:
    """Scanner *name* as the release asset *tool*, its runtime pinning *tool* too, so
    that what is left to report is the tool and not the two rows disagreeing."""
    facets = _planted(name, route=opsf.ImageRoute.RELEASE_ASSET, tool=tool)
    runtime = facets.runtime.model_copy(update={"tool_versions_key": tool})
    return facets.model_copy(update={"runtime": runtime})


def test_the_image_routes_are_the_seven_the_register_names() -> None:
    assert [route.value for route in opsf.ImageRoute] == [
        "release_asset",
        "dependencies_install",
        "gem_bundle",
        "os_package",
        "ash_wheel",
        "shared_tool",
        "not_in_image",
    ]
    assert issubclass(opsf.ImageRoute, str)


def test_the_image_row_follows_the_platform_row() -> None:
    names = opsf.OPERATIONAL_FACET_NAMES

    assert names.index("image") == names.index("platforms") + 1
    assert tuple(opsf.ScannerOperationalFacets.model_fields) == names


def test_every_scanner_declares_the_route_the_dockerfile_gives_it() -> None:
    declared = {
        _ops(cls).scanner_name: _ops(cls).image.route.value for cls in SCANNER_CLASSES
    }

    assert len(_IMAGE_ROUTES) == 23
    assert declared == _IMAGE_ROUTES
    assert "os_package" not in declared.values(), "no shipped scanner uses it yet"


# --- the row's own shape rules, each refused and each beside an accepted sibling ----


def _facet(**fields):
    return opsf.ImageFacet(**fields)


_IMAGE_REFUSED = {
    "not_in_image with no reason": (
        lambda: _facet(route=opsf.ImageRoute.NOT_IN_IMAGE),
        "a not_in_image image row states its reason",
    ),
    "not_in_image with a blank reason": (
        lambda: _facet(route=opsf.ImageRoute.NOT_IN_IMAGE, reason="  "),
        "a not_in_image image row states its reason",
    ),
    "not_in_image naming a tool": (
        lambda: _facet(route=opsf.ImageRoute.NOT_IN_IMAGE, reason="r", tool="syft"),
        "a not_in_image image row names no tool and no version check",
    ),
    "not_in_image with a version check": (
        lambda: _facet(
            route=opsf.ImageRoute.NOT_IN_IMAGE,
            reason="r",
            version_check=("syft", "--version"),
        ),
        "a not_in_image image row names no tool and no version check",
    ),
    "release_asset with no tool": (
        lambda: _facet(route=opsf.ImageRoute.RELEASE_ASSET),
        "a release_asset image row names its tool",
    ),
    "release_asset with a blank tool": (
        lambda: _facet(route=opsf.ImageRoute.RELEASE_ASSET, tool=" "),
        "a release_asset image row names its tool",
    ),
    "shared_tool with no tool": (
        lambda: _facet(route=opsf.ImageRoute.SHARED_TOOL),
        "a shared_tool image row names its tool",
    ),
    "os_package with no package": (
        lambda: _facet(route=opsf.ImageRoute.OS_PACKAGE),
        "an os_package image row names its package",
    ),
    "a note line that is not a comment": (
        lambda: _facet(route=opsf.ImageRoute.ASH_WHEEL, dockerfile_note=("RUN true",)),
        "an image note line is a Dockerfile comment",
    ),
    "a version check with a blank word": (
        lambda: _facet(
            route=opsf.ImageRoute.RELEASE_ASSET,
            tool="syft",
            version_check=("syft", " "),
        ),
        "an image version check holds no blank word",
    ),
}


@pytest.mark.parametrize("case", sorted(_IMAGE_REFUSED))
def test_an_image_row_that_breaks_its_shape_rule_refuses_construction(
    case: str,
) -> None:
    build, fragment = _IMAGE_REFUSED[case]

    with pytest.raises(ValueError, match=re.escape(fragment)):
        build()


_IMAGE_ACCEPTED = {
    "a release asset": lambda: _facet(
        route=opsf.ImageRoute.RELEASE_ASSET,
        tool="syft",
        version_check=("syft", "--version"),
    ),
    "a shared tool": lambda: _facet(route=opsf.ImageRoute.SHARED_TOOL, tool="trivy"),
    "a dependencies install": lambda: _facet(
        route=opsf.ImageRoute.DEPENDENCIES_INSTALL
    ),
    "a gem bundle": lambda: _facet(route=opsf.ImageRoute.GEM_BUNDLE),
    "an ASH wheel": lambda: _facet(route=opsf.ImageRoute.ASH_WHEEL),
    "an os package": lambda: _facet(route=opsf.ImageRoute.OS_PACKAGE, package="jq"),
    "a not_in_image row with its reason": lambda: _facet(
        route=opsf.ImageRoute.NOT_IN_IMAGE, reason="the user installs it"
    ),
    "notes that are comments": lambda: _facet(
        route=opsf.ImageRoute.ASH_WHEEL, dockerfile_note=("# a comment", "#")
    ),
}


@pytest.mark.parametrize("case", sorted(_IMAGE_ACCEPTED))
def test_an_image_row_that_keeps_its_shape_rules_is_accepted(case: str) -> None:
    assert isinstance(_IMAGE_ACCEPTED[case](), opsf.ImageFacet)


def test_an_image_row_is_a_frozen_value_with_every_optional_field_empty() -> None:
    facet = _facet(route=opsf.ImageRoute.ASH_WHEEL)

    assert (facet.tool, facet.package, facet.reason) == (None, None, None)
    assert (facet.version_check, facet.dockerfile_note) == ((), ())
    with pytest.raises(ValueError):
        facet.tool = "syft"
    with pytest.raises(ValueError):
        _facet(route=opsf.ImageRoute.ASH_WHEEL, unknown_field=1)


# --- the route against the scanner's own runtime --------------------------------------


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_the_image_route_agrees_with_the_runtime(cls) -> None:
    facets = _ops(cls)

    problems = image_route_problems(
        facets, _tools_other_rows_install(facets.scanner_name), _system_package_keys()
    )

    assert problems == [], facets.scanner_name


def test_a_release_asset_on_bandit_fails() -> None:
    planted = _planted("bandit", route=opsf.ImageRoute.RELEASE_ASSET, tool="bandit")

    problems = image_route_problems(planted, frozenset(), frozenset())

    assert any("pinned-binary runtime" in problem for problem in problems), problems


def test_a_release_asset_for_a_tool_nothing_pins_fails() -> None:
    planted = _planted(
        "gitleaks", route=opsf.ImageRoute.RELEASE_ASSET, tool="gitleaks-next"
    )

    problems = image_route_problems(planted, frozenset(), frozenset())

    assert any("is not pinned in TOOL_VERSIONS" in problem for problem in problems)
    assert any("is not the runtime's TOOL_VERSIONS key" in p for p in problems)


def test_a_shared_tool_that_no_other_row_installs_fails() -> None:
    planted = _planted("trivy-repo", route=opsf.ImageRoute.SHARED_TOOL, tool="nothing")

    problems = image_route_problems(
        planted, _tools_other_rows_install("trivy-repo"), frozenset()
    )

    assert any("no other scanner's row installs 'nothing'" in p for p in problems)


def test_a_shared_tool_that_only_the_scanner_itself_installs_fails() -> None:
    """trivy installs trivy; trivy-repo borrows it. A trivy row that claimed to borrow
    it would borrow from itself."""
    planted = _planted("trivy", route=opsf.ImageRoute.SHARED_TOOL, tool="trivy")

    problems = image_route_problems(
        planted, _tools_other_rows_install("trivy"), frozenset()
    )

    assert any("no other scanner's row installs 'trivy'" in p for p in problems)
    assert "trivy" in _tools_other_rows_install("trivy-repo")
    assert "trivy" not in _tools_other_rows_install("trivy")


def test_a_shared_tool_that_is_not_the_one_the_scanner_runs_fails() -> None:
    """trivy-repo runs trivy, and another row installs syft, so a row that borrowed
    syft passes the check that someone installs it. Only the runtime says the scanner
    would run another tool."""
    other_rows = _tools_other_rows_install("trivy-repo")
    borrowed = _planted("trivy-repo", route=opsf.ImageRoute.SHARED_TOOL, tool="syft")
    own = _planted("trivy-repo", route=opsf.ImageRoute.SHARED_TOOL, tool="trivy")

    problems = image_route_problems(borrowed, other_rows, frozenset())

    assert "syft" in other_rows
    assert len(problems) == 1, problems
    assert "the scanner runs 'trivy', not 'syft'" in problems[0]
    assert image_route_problems(own, other_rows, frozenset()) == []


def test_a_pinned_tool_with_no_download_table_fails(monkeypatch) -> None:
    """A pin says which release and the table says which files, so a tool can have
    the first and not the second. The row is planted without the table, which is
    reported, and with it, which is not."""
    monkeypatch.setitem(tool_downloads.TOOL_VERSIONS, "pinned-only", "v1.0.0")
    planted = _planted_pinned("gitleaks", "pinned-only")

    problems = image_route_problems(planted, frozenset(), frozenset())

    assert len(problems) == 1, problems
    assert "'pinned-only' has no release-asset download table" in problems[0]
    monkeypatch.setattr(tool_downloads, "downloadable_tools", lambda: ["pinned-only"])
    assert image_route_problems(planted, frozenset(), frozenset()) == []


def test_a_gem_bundle_on_a_pinned_binary_fails() -> None:
    planted = _planted("gitleaks", route=opsf.ImageRoute.GEM_BUNDLE)

    problems = image_route_problems(planted, frozenset(), frozenset())

    assert any("Ruby gem runtime" in problem for problem in problems), problems


def test_an_ash_wheel_on_a_uv_tool_fails() -> None:
    planted = _planted("bandit", route=opsf.ImageRoute.ASH_WHEEL)

    problems = image_route_problems(planted, frozenset(), frozenset())

    assert any("in-process or node-subcommand" in problem for problem in problems)


def test_an_os_package_the_image_register_does_not_name_fails() -> None:
    planted = _planted("bandit", route=opsf.ImageRoute.OS_PACKAGE, package="bandit")

    assert image_route_problems(planted, frozenset(), frozenset()) != []
    assert image_route_problems(planted, frozenset(), frozenset({"bandit"})) == []


def has_install_commands(instance, target_platform: str, arch: str) -> bool:
    return len(instance.get_installation_commands(target_platform, arch)) > 0


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_dependencies_install_means_the_scanner_declares_install_commands(
    cls, _instances
) -> None:
    """``ash dependencies install`` is the route, so a scanner that claims it has
    something for the command to run."""
    facets = _ops(cls)

    if facets.image.route is opsf.ImageRoute.DEPENDENCIES_INSTALL:
        assert has_install_commands(_instances[cls], "linux", "amd64"), (
            facets.scanner_name
        )


def test_the_install_command_reader_has_a_positive_and_a_negative_control(
    _instances,
) -> None:
    """GuardDog installs nowhere on Windows and says so by declaring no command."""
    guarddog = _instances[_class_named("guarddog")]

    assert has_install_commands(guarddog, "linux", "amd64")
    assert not has_install_commands(guarddog, "windows", "amd64")


def test_the_two_scanners_left_out_of_the_image_say_why() -> None:
    reasons = {
        name: _ops(_class_named(name)).image.reason
        for name in ("snyk-code", "ferret-scan")
    }

    assert [n for n, r in sorted(_IMAGE_ROUTES.items()) if r == "not_in_image"] == [
        "ferret-scan",
        "snyk-code",
    ]
    assert "installed by the user" in reasons["snyk-code"]
    assert "account" in reasons["snyk-code"]
    assert "ferret-scan" in reasons["ferret-scan"]
    assert "another way" in reasons["ferret-scan"]


# --- what the image row says against the Dockerfile text -------------------------------


def comment_block_above(lines: list[str], prefix: str) -> list[str]:
    """The consecutive comment lines directly above the first line that starts with
    *prefix*; empty when a blank line or an instruction sits there."""
    index = next(i for i, line in enumerate(lines) if line.startswith(prefix))
    start = index
    while start > 0 and lines[start - 1].startswith("#"):
        start -= 1
    return lines[start:index]


def contains_run(lines: list[str], run: tuple[str, ...]) -> bool:
    """Whether *run* is a stretch of consecutive lines of *lines*."""
    width = len(run)
    return width > 0 and any(
        tuple(lines[start : start + width]) == run
        for start in range(len(lines) - width + 1)
    )


def version_check_runs(text: str) -> set[tuple[str, ...]]:
    """The ``RUN <tool> --version`` and ``RUN <tool> version`` argv in a Dockerfile."""
    return {
        tuple(match.group(1).split())
        for match in re.finditer(
            r"^RUN (\S+ (?:--version|version))(?:\s|$)", text, flags=re.MULTILINE
        )
    }


def test_the_dockerfile_readers_have_positive_and_negative_controls() -> None:
    lines = ["# one", "# two", "ARG A_VERSION=1", "", "ARG B_VERSION=2", "# three"]

    assert comment_block_above(lines, "ARG A_VERSION=") == ["# one", "# two"]
    assert comment_block_above(lines, "ARG B_VERSION=") == []
    assert contains_run(lines, ("# one", "# two"))
    assert not contains_run(lines, ("# two", "# one"))
    assert not contains_run(lines, ("# one", "# tw0"))
    assert not contains_run(lines, ())
    planted = "RUN foo --version\nRUN bar version\n# RUN baz --version\nRUN qux -v\n"
    assert version_check_runs(planted) == {("foo", "--version"), ("bar", "version")}
    assert _LICENSING.search("# MIT-licensed, so its entry in THIRD_PARTY_LICENSES")
    assert _LICENSING.search("# links to it. It is GPL-3.0-only, so")
    assert not _LICENSING.search("# gitleaks backs the builtin gitleaks scanner.")
    assert not _LICENSING.search("# Some gems ship files mode 777 (lightly, which")


@pytest.mark.parametrize(
    "spelling",
    [
        "GPLv3",
        "gplv3",
        "GPLV3",
        "AGPL-3.0",
        "agpl-3.0",
        "Agpl-3.0",
        "LGPL-2.1",
        "lgpl-2.1",
        "Lgpl-2.1",
    ],
)
def test_the_licensing_filter_catches_each_spelling_of_a_gpl_family_license(
    spelling: str,
) -> None:
    assert _LICENSING.search(f"# It is {spelling}, so")
    assert _LICENSING.search(f"# {spelling} only.")


def test_the_licensing_filter_leaves_gpl_letters_inside_another_word_alone() -> None:
    assert not _LICENSING.search("# gplot draws the graph.")
    assert not _LICENSING.search("# The xagpl cache is private.")


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_an_image_note_is_a_verbatim_run_of_dockerfile_comments(cls) -> None:
    note = _ops(cls).image.dockerfile_note

    if note:
        assert all(line.startswith("#") for line in note)
        assert contains_run(_DOCKERFILE_LINES, note), _ops(cls).scanner_name


def test_no_image_note_says_anything_about_licensing() -> None:
    notes = [
        line for cls in SCANNER_CLASSES for line in _ops(cls).image.dockerfile_note
    ]
    licensing_lines = {
        line
        for line in _DOCKERFILE_LINES
        if line.startswith("#") and _LICENSING.search(line)
    }

    assert notes, "no scanner carries a note, so the check below would pass on nothing"
    assert licensing_lines, "the Dockerfile has licensing comments to keep out"
    assert [line for line in notes if _LICENSING.search(line)] == []
    assert not licensing_lines & set(notes)


@pytest.mark.parametrize("name", ["betterleaks", "hadolint"])
def test_a_scanner_whose_dockerfile_comment_is_about_licensing_carries_no_note(
    name: str,
) -> None:
    block = comment_block_above(_DOCKERFILE_LINES, f"ARG {name.upper()}_VERSION=")

    assert any(_LICENSING.search(line) for line in block), name
    assert _ops(_class_named(name)).image.dockerfile_note == ()


#: The note each release-asset scanner's row carries, written out. A scanner whose
#: Dockerfile comment is about licensing, or that has none, carries no note.
_RELEASE_ASSET_NOTES: dict[str, tuple[str, ...]] = {
    "actionlint": (
        "# actionlint backs the builtin actionlint scanner. Same pinned-asset path as syft and",
        "# grype.",
    ),
    "betterleaks": (),
    "cfn-guard": (
        "# cfn-guard, a builtin scanner, and the AWS Guard Rules Registry it evaluates",
        "# templates against. The binary comes from its pinned release asset like the tools",
        "# above. The rules archive is pinned the same way (RULES_BUNDLES in",
        "# utils/tool_downloads.py) and installed here as root, mode 0755/0644, so the scan",
        "# user cannot rewrite the rules a later scan trusts. `ash dependencies install`",
        "# below finds the bundle already in place, its rule files matching the contents",
        "# pinned beside the archive digest, and leaves it alone.",
        "# Under /usr/share rather than /deps, whose cache directories stay writable for the",
        "# scanners: the bundle and every directory above it are root's and writable by no one",
        "# else, which `--assert-root-only` checks here and again in the final stage.",
    ),
    "gitleaks": (
        "# gitleaks backs the builtin gitleaks scanner, which runs beside detect-secrets.",
    ),
    "grype": (),
    "hadolint": (),
    "syft": (),
    "trivy": (),
}


def test_the_written_out_notes_name_every_release_asset_scanner() -> None:
    assert sorted(_RELEASE_ASSET_NOTES) == [
        name
        for name, route in sorted(_IMAGE_ROUTES.items())
        if route == "release_asset"
    ]


@pytest.mark.parametrize("name", sorted(_RELEASE_ASSET_NOTES))
def test_a_release_asset_note_is_the_comment_above_its_version_argument(
    name: str,
) -> None:
    """The note is what the Dockerfile says directly above the scanner's version
    argument, unless that comment is about licensing or there is none, when it is
    nothing. The notes are written out above, so the filter that keeps licensing
    words out of a note is not also what decides which note is expected."""
    image = _ops(_class_named(name)).image
    block = comment_block_above(
        _DOCKERFILE_LINES, f"ARG {image.tool.upper().replace('-', '_')}_VERSION="
    )
    expected = _RELEASE_ASSET_NOTES[name]

    assert image.dockerfile_note == expected, name
    if expected:
        assert tuple(block) == expected, name
    else:
        assert not block or any(_LICENSING.search(line) for line in block), name
    assert image.version_check == (image.tool, "--version"), name


#: The stage the pinned tools are installed in. ``ci`` and ``non-root`` are built on
#: it. ``uv-reqs`` builds the wheel and installs only uv, so a tool installed in that
#: stage is not in the image.
_TOOL_STAGE = "core"


def stage_installs(text: str, stage: str, tool: str) -> bool:
    """Whether a line of *stage* in the Dockerfile *text* installs *tool* with the
    pinned-tool installer. A comment installs nothing, a continued line is one line,
    and a stage the file does not have installs nothing."""
    body = dockerfile_stages(text).get(stage.lower(), "")
    lines = [line for line in body.splitlines() if not line.lstrip().startswith("#")]
    return f"install-pinned-tool {tool} -b " in "\n".join(lines).replace("\\\n", " ")


def test_the_install_reader_has_controls_for_a_comment_and_for_another_stage() -> None:
    planted = (
        "FROM base AS builder\n"
        "RUN with-retry 'install-pinned-tool only-in-builder -b /usr/local/bin'\n"
        "FROM base AS core\n"
        "RUN with-retry 'install-pinned-tool syft -b /usr/local/bin'\n"
        "# RUN with-retry 'install-pinned-tool commented -b /usr/local/bin'\n"
        "  # RUN with-retry 'install-pinned-tool indented -b /usr/local/bin'\n"
        "RUN with-retry 'install-pinned-tool grype -b /usr/local/bin' && \\\n"
        "    with-retry 'install-pinned-tool crane -b /usr/local/bin'\n"
        "RUN with-retry 'install-pinned-tool syft-extra -b /usr/local/bin'\n"
    )

    for tool in ("syft", "grype", "crane", "syft-extra"):
        assert stage_installs(planted, "core", tool), tool
    # A commented line is not an install, and neither is a line of another stage.
    for tool in ("commented", "indented", "only-in-builder", "syft-extr"):
        assert not stage_installs(planted, "core", tool), tool
    assert stage_installs(planted, "builder", "only-in-builder")
    assert not stage_installs(planted, "builder", "syft")
    assert not stage_installs(planted, "missing", "syft")


def test_ci_and_non_root_are_built_on_the_stage_that_installs_the_tools() -> None:
    built_on = {
        name.lower(): base
        for base, name in re.findall(
            r"^FROM\s+(?:--\S+\s+)*(\S+)\s+AS\s+(\S+)\s*$",
            _DOCKERFILE_TEXT,
            flags=re.IGNORECASE | re.MULTILINE,
        )
    }

    assert built_on["ci"] == _TOOL_STAGE
    assert built_on["non-root"] == _TOOL_STAGE


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_a_release_asset_is_installed_by_the_pinned_tool_installer_and_no_other_is(
    cls,
) -> None:
    facets = _ops(cls)
    key = facets.runtime.tool_versions_key

    if facets.image.route is opsf.ImageRoute.RELEASE_ASSET:
        assert stage_installs(_DOCKERFILE_TEXT, _TOOL_STAGE, facets.image.tool)
    elif facets.image.route is opsf.ImageRoute.DEPENDENCIES_INSTALL and key:
        installed_in = [
            stage
            for stage in dockerfile_stages(_DOCKERFILE_TEXT)
            if stage_installs(_DOCKERFILE_TEXT, stage, key)
        ]
        assert installed_in == [], (
            f"{facets.scanner_name} gets the pinned {key} from dependencies install"
        )


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=lambda c: c.__name__)
def test_a_version_check_is_a_run_line_of_the_dockerfile(cls) -> None:
    check = _ops(cls).image.version_check

    if check:
        assert check in version_check_runs(_DOCKERFILE_TEXT), _ops(cls).scanner_name


def test_every_version_check_the_dockerfile_runs_is_declared() -> None:
    declared = {tuple(_ops(cls).image.version_check) for cls in SCANNER_CLASSES}
    declared |= {tuple(step.version_check) for step in _ir().ENGINE_IMAGE_STEPS}
    found = version_check_runs(_DOCKERFILE_TEXT)

    assert len(found) >= 12, sorted(found)
    assert found <= declared, sorted(found - declared)
