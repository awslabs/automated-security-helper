# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The register consistency gate: declared facets against observed columns.

The facets register (automated_security_helper/base/scanner_facets.py) says,
per scanner and facet, whether the native output maps (MAPPED), could map but
is discarded today (DROPPED), cannot be there (N/A), or has not been read from
a real run (UNCONFIRMED). The conformance rows beside this module prove one cell at a time that a declaration is not a lie
(``resource_id`` against the code and one fixture). This module adds the
corpus-wide, column-level direction: it joins what each scanner DECLARES with
what the committed fixtures OBSERVABLY carry in the flat row (the one place
every facet lands, ``FlatVulnerability.from_sarif_result``), and fails on any
disagreement:

- MAPPED, and the observed column is empty across the scanner's whole corpus:
  the tool's output moved or an adapter regression dropped the mapping.
- MAPPED, and the scanner has no corpus to observe (no committed fixture, no
  registered prep for its native format, or fixtures that hold no result): the
  verdict names the fixture that is missing. The gate cannot tell drift from
  never-measured, so it refuses the cell; it does not guess.
- N/A, and the observed column is populated: the binding-column contamination
  failure mode the register's deny discipline exists for (a secret hash or a
  path shoved into a column that other code trusts), generalized to every
  facet (decision G9: FAIL, not warn).
- DROPPED, and the observed column is populated: the cell is out of date;
  redeclare it MAPPED.
- UNCONFIRMED, and the observed column is empty or the scanner has no corpus:
  a fixture owed, listed in the gate table and never failed. The owed set must
  equal the register's UNCONFIRMED cells, excluded columns included.
- UNCONFIRMED, and the observed column is populated: the cell is settled or
  contaminated, so it FAILS; redeclare it with the evidence, or fix the adapter.

Contract (the waiver rule, asserted by the test below): the register is the
only place the truth lives. There is no suppression list, skip list or
allowlist in this gate; the one waiver is REDECLARING the cell in the
scanner's own register row (with the reason the register requires), which is
itself reviewed. A failure message names the cell and both exits: fix the
adapter, or redeclare the cell.

What is observed, said plainly. The observation surface is the flat row built
by ``FlatVulnerability.from_sarif_result`` from each result of the scanner's
committed fixtures: every ``*.sarif`` the scanner's fixture directory holds,
plus the registered preps for the native formats that have a pure, tool-free
adapter function (``_PREPS``). No tool is run and no network is touched. A
scanner whose only committed fixtures are native non-SARIF output with no
registered prep has no corpus here; its MAPPED cells FAIL naming the missing
fixture or prep, which is a follow-up row (author the fixture, or register the
prep), never a waiver. ``remediation_text``, ``extras`` and ``column`` have no
flat column (decision G10) and are excluded from v1 by name in
``FACET_COLUMNS``.

The pure verdict function (``judge``) is separate from the corpus read so
that planted controls can drive every drift class over synthetic corpora, and
the corpus read has its own non-vacuity controls.
"""

from __future__ import annotations

import functools
import importlib
import json
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator, Mapping, Optional

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.base.facet_conformance import (
    FACET_COLUMNS,
    Verdict,
    judge,
    observed_counts,
    text_present,
)
from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    SCANNER_FACETS_ATTR,
    FacetDecl,
    FacetState,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Result, SarifReport
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES
from automated_security_helper.utils.scanner_tool_types import _class_config_name
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit

#: The shared enumeration (tests/utils/scanner_enumeration.py).
SCANNER_CLASSES, _REMAINING_LOAD_ERRORS = load_scanner_universe()

_FIXTURES = Path(__file__).resolve().parents[2] / "test_data" / "scanners"


# --------------------------------------------------------------------------
# The facet -> observed-column map (GC-1) lives in base/facet_conformance.py,
# where the conformance harness reads the same verdicts; it is total over
# FACET_NAMES (asserted below).
# --------------------------------------------------------------------------


def test_the_facet_map_is_total_over_the_vocabulary() -> None:
    """Adding a facet to the vocabulary forces an observation decision here."""
    assert set(FACET_COLUMNS) == set(FACET_NAMES), (
        "FACET_COLUMNS and FACET_NAMES disagree: only in the map "
        f"{sorted(set(FACET_COLUMNS) - set(FACET_NAMES))}, only in the "
        f"vocabulary {sorted(set(FACET_NAMES) - set(FACET_COLUMNS))}. Every "
        "facet is observed through a flat column or declared excluded by name."
    )
    assert list(FACET_COLUMNS) == list(FACET_NAMES), "keep the map in vocabulary order"


def test_every_observed_column_exists_on_the_flat_row() -> None:
    members = set(FlatVulnerability.model_fields) | {
        name
        for name, attr in vars(FlatVulnerability).items()
        if isinstance(attr, property)
    }
    for facet, observation in FACET_COLUMNS.items():
        if observation.excluded is not None:
            assert not observation.columns and observation.populated is None, facet
            assert observation.excluded.strip(), f"{facet}: exclusion needs a reason"
            continue
        assert observation.columns and observation.populated is not None, facet
        missing = [c for c in observation.columns if c not in members]
        assert not missing, f"{facet} reads flat columns that do not exist: {missing}"


def test_the_exclusions_are_exactly_the_facets_with_no_flat_column() -> None:
    excluded = {f for f, o in FACET_COLUMNS.items() if o.excluded is not None}
    assert excluded == {"column", "remediation_text", "extras"}


# --------------------------------------------------------------------------
# The verdict (GC-2): a pure join of declared state and observed counts.
# --------------------------------------------------------------------------

# Verdict, judge, FACET_COLUMNS, observed_counts and text_present are imported from
# base/facet_conformance.py (Observation is defined there and not imported here): the
# harness behind `ash plugin verify` judges cells with the same function, over
# transcripts instead of CorpusSpecs.


# --------------------------------------------------------------------------
# The corpus: registered scanners, their fixtures, the observed frame (GC-1).
# --------------------------------------------------------------------------


def _name(cls: type) -> str:
    name = _class_config_name(cls)
    assert name, f"{cls.__qualname__}: no config name"
    return name


def _declared(cls: type) -> dict[str, FacetState]:
    row = vars(cls)[SCANNER_FACETS_ATTR]
    return {facet: getattr(row, facet).state for facet in FACET_NAMES}


@dataclass(frozen=True)
class CorpusSpec:
    """Where a scanner's committed fixtures are and how they become results."""

    #: Directory under tests/test_data/scanners.
    directory: str
    #: Glob (relative to the directory) of SARIF files read as the tool wrote them.
    sarif: tuple[str, ...] = ()
    #: Name of a registered prep (``_PREPS``) over native, non-SARIF fixtures.
    prep: Optional[str] = None
    #: What a maintainer should author when the corpus is missing or empty.
    missing: str = ""


#: scanner config name -> its corpus. A scanner absent from this table fails the
#: registry-agreement test, so a new scanner forces a decision (a corpus, or a
#: declared absence with the fixture to author).
CORPORA: Mapping[str, Optional[CorpusSpec]] = {
    "actionlint": CorpusSpec("actionlint", prep="actionlint"),
    "bandit": CorpusSpec("bandit", sarif=("captured/*.sarif",)),
    "betterleaks": CorpusSpec(
        "betterleaks", sarif=("captured/*.sarif",), prep="betterleaks"
    ),
    "cdk-nag": CorpusSpec("cdk", prep="cdk-nag"),
    "cfn-guard": CorpusSpec(
        "cfn_lint_guard", sarif=("captured/cfn-guard-*.sarif",), prep="cfn-guard"
    ),
    "cfn-lint": CorpusSpec(
        "cfn_lint_guard", sarif=("captured/cfn-lint-*.sarif",), prep="cfn-lint"
    ),
    "cfn-nag": CorpusSpec(
        "cfn_nag", sarif=("captured/cfn_nag-0.8.10-*.sarif",), prep="cfn-nag"
    ),
    "checkov": CorpusSpec("checkov", sarif=("captured/*.sarif",), prep="checkov"),
    "detect-secrets": CorpusSpec("detect_secrets", prep="detect-secrets"),
    "ferret-scan": CorpusSpec(
        "ferret-scan", sarif=("captured/*.sarif",), prep="ferret-scan"
    ),
    "gitleaks": CorpusSpec("gitleaks", sarif=("gitleaks-*.sarif",), prep="gitleaks"),
    "grype": CorpusSpec("grype", sarif=("captured/*.sarif",), prep="grype"),
    "guarddog": CorpusSpec("guarddog", prep="guarddog"),
    "hadolint": CorpusSpec("hadolint", sarif=("captured/*.sarif",)),
    "mcp-config": CorpusSpec("mcp_config", sarif=("captured/*.sarif",)),
    "npm-audit": CorpusSpec("npmaudit", prep="npm-audit"),
    "opengrep": CorpusSpec("opengrep", sarif=("captured/*.sarif",)),
    "semgrep": CorpusSpec("semgrep", sarif=("captured/*.sarif",)),
    # No corpus until a licensed `snyk code test --sarif` run is committed under
    # captured/: the authored file beside it is written to match the adapter, so
    # it is not read as evidence of the tool (see the README in the directory).
    # The register's snyk-code cells are UNCONFIRMED for that reason. When a
    # capture lands, point this row at "captured/*.sarif" with prep="snyk-code".
    "snyk-code": CorpusSpec(
        "snyk",
        missing="no snyk SARIF from a licensed run is committed; commit "
        "`snyk code test --sarif` output under snyk/captured/ (the authored "
        "shape under snyk/authored is not evidence of the tool)",
    ),
    "syft": CorpusSpec(
        "syft",
        missing="syft commits its native SBOM JSON only (syft/syft.src.json); "
        "commit a capture of the scanner's SARIF report",
    ),
    "trivy": CorpusSpec("trivy", sarif=("*.sarif", "captured/*.sarif"), prep="trivy"),
    "trivy-repo": CorpusSpec(
        "trivy", sarif=("*.sarif", "captured/*.sarif"), prep="trivy"
    ),
    "zizmor": CorpusSpec("zizmor", sarif=("*.sarif",)),
}

#: Why a scanner with no CorpusSpec has none (named, not authored).
_NO_FIXTURE_DIRECTORY: dict[str, str] = {}


def _load_sarif(path: Path) -> SarifReport:
    return SarifReport.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _prep_cfn_guard(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
        CfnGuardScanner,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            report = _load_sarif(path)
            yield report, CfnGuardScanner.normalize_results(report, "template.yaml")


def _prep_cfn_lint(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
        CfnLintScanner,
        attach_cfn_lint_resources,
        cfn_lint_resources,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            report = _load_sarif(path)
            # The resource comes from the JSON run beside it, when one is
            # committed. The scanner attaches it as each batch is read, before
            # normalize_report relocates the results, so the keys still match.
            companion = path.with_suffix(".json")
            if companion.is_file():
                attach_cfn_lint_resources(
                    report,
                    cfn_lint_resources(
                        json.loads(companion.read_text(encoding="utf-8"))
                    ),
                )
            # normalize_report reads no instance state: it locates results,
            # maps severities and sorts rules in place. An uninitialized
            # instance stands in for the scanner, so the call keeps its types.
            CfnLintScanner.__new__(CfnLintScanner).normalize_report(report)
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_cfn_nag(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        attach_cfn_nag_resources,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            report = _load_sarif(path)
            attach_cfn_nag_resources(report)
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _report_with_rules(tool_name: str, rules: list[Any]) -> SarifReport:
    """A report whose one run declares *rules* on its driver and holds no
    results: the results are yielded beside it, and the rule-level facets
    (help link, tags) are read from the run."""
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "rules": [
                                rule.model_dump(mode="json", exclude_none=True)
                                for rule in rules
                            ],
                        }
                    },
                    "results": [],
                }
            ],
        }
    )


def _prep_guarddog(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
        convert_guarddog_scan_result,
        manifest_line_for,
    )

    captured = _FIXTURES / spec.directory / "captured"
    for path in sorted(captured.glob("scan_*.json")):
        ecosystem = path.stem.split("_")[1]
        document = json.loads(path.read_text(encoding="utf-8"))
        converted = convert_guarddog_scan_result(
            document, uri_prefix="", ecosystem=ecosystem, include_capabilities=True
        )
        yield (
            _report_with_rules("guarddog", list(converted.rules.values())),
            list(converted.results),
        )
    # Verify mode is where the adapter writes package identity: each committed
    # verify capture is a list of {dependency, version, result} entries over
    # the manifest committed beside it, converted the way the scanner's own
    # verify path converts them.
    for path in sorted(captured.glob("verify_*.json")):
        ecosystem = path.stem.split("_")[1]
        manifest = path.with_suffix(".txt")
        manifest_text = manifest.read_text(encoding="utf-8")
        for entry in json.loads(path.read_text(encoding="utf-8")):
            converted = convert_guarddog_scan_result(
                entry["result"],
                uri_prefix="",
                ecosystem=ecosystem,
                include_capabilities=True,
                dependency=(entry["dependency"], entry["version"]),
                manifest_uri=manifest.name,
                manifest_line=manifest_line_for(manifest_text, entry["dependency"]),
            )
            yield (
                _report_with_rules("guarddog", list(converted.rules.values())),
                list(converted.results),
            )


def _prep_checkov(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        attach_checkov_guidelines,
        attach_checkov_resources,
        checkov_guidelines,
        checkov_resources,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            sarif = json.loads(path.read_text(encoding="utf-8"))
            side = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
            attach_checkov_resources(sarif, checkov_resources(side))
            attach_checkov_guidelines(sarif, checkov_guidelines(side))
            report = SarifReport.model_validate(sarif)
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_detect_secrets(
    spec: CorpusSpec,
) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )

    for path in sorted((_FIXTURES / spec.directory / "captured").glob("*.json")):
        results = []
        for _key, secrets in json.loads(path.read_text(encoding="utf-8")):
            for secret in secrets:
                results.append(
                    DetectSecretsScanner.build_secret_result(
                        finding_type=secret["type"],
                        uri=secret["filename"],
                        line_number=secret["line_number"],
                        start_column=secret.get("ash_start_column"),
                    )
                )
        report = SarifReport.model_validate({"version": "2.1.0", "runs": []})
        yield report, results


def _prep_gitleaks(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
        GitleaksScanner,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            report = GitleaksScanner.normalize_results(_load_sarif(path))
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_betterleaks(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_betterleaks_plugins.betterleaks_scanner import (
        BetterleaksScanner,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            report = BetterleaksScanner.normalize_results(_load_sarif(path))
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_actionlint(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
        build_sarif,
    )

    for path in sorted((_FIXTURES / spec.directory).glob("actionlint-*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        document = build_sarif(payload, 1 if payload.get("errors") else 0)
        report = SarifReport.model_validate(document)
        yield report, [r for run in report.runs or [] for r in run.results or []]


def _materialized(template: Path, scratch: Path) -> Path:
    """``template`` copied under ``scratch`` with every ``.fixture`` suffix stripped.

    The suffix dance of ``tests/utils/trivy_fixture.py``: lockfiles naming
    advisory-bearing versions are committed under a name dependency scanners
    of this repository do not read, and materialized for a run.
    """
    import shutil

    destination = scratch / "src"
    shutil.copytree(template, destination)
    for path in sorted(destination.rglob("*.fixture")):
        path.rename(path.with_name(path.name[: -len(".fixture")]))
    return destination


def _prep_ferret_scan(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    """The committed `ferret-scan --format sarif` capture through the adapter's
    own base-relative URI resolution, the step it applies before the report is
    built."""
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        _resolve_sarif_uri_base_ids,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            document = json.loads(path.read_text(encoding="utf-8"))
            _resolve_sarif_uri_base_ids(document)
            report = SarifReport.model_validate(document)
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_grype(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    """The committed `grype -o sarif` capture through the adapter's own
    post-processing (URIs, package identity, fix state). The scan target is an
    empty directory: the capture was taken over an SBOM, so no lockfile sits
    beside it for the package-path lookup."""
    import tempfile

    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )

    with tempfile.TemporaryDirectory(prefix="facets-grype-corpus-") as scratch:
        for pattern in spec.sarif:
            for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
                # The step reads no instance state; building the scanner would
                # need a run context this pure read has no use for.
                report = GrypeScanner.__new__(GrypeScanner)._post_process_sarif(
                    _load_sarif(path), [], Path(scratch)
                )
                yield (
                    report,
                    [r for run in report.runs or [] for r in run.results or []],
                )


def _prep_snyk_code(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    """The committed SARIF through the adapter's own rule-CWE normalization,
    the one step the scanner applies before it builds the report."""
    from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
        normalize_rule_cwe_into_tags,
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            document = normalize_rule_cwe_into_tags(
                json.loads(path.read_text(encoding="utf-8"))
            )
            report = SarifReport.model_validate(document)
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_trivy(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    """The committed SARIF through the adapter's own pure steps.

    Package identity and the fixed version read the message against the
    materialized fixture lockfiles; a misconfiguration's resource comes from
    the JSON capture beside its SARIF, when there is one.
    """
    import tempfile

    from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
        attach_trivy_resources,
        trivy_misconfig_resources,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
    )

    with tempfile.TemporaryDirectory(prefix="facets-trivy-corpus-") as scratch:
        target = _materialized(
            _FIXTURES / spec.directory / "fixture_repo", Path(scratch)
        )
        for pattern in spec.sarif:
            for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
                report = TrivyScanner._attach_package_identity(
                    _load_sarif(path), target
                )
                companion = path.with_suffix(".json")
                if companion.is_file():
                    attach_trivy_resources(
                        report,
                        trivy_misconfig_resources(
                            json.loads(companion.read_text(encoding="utf-8"))
                        ),
                    )
                yield (
                    report,
                    [r for run in report.runs or [] for r in run.results or []],
                )


def _prep_npm_audit(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    import tempfile

    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScanner,
    )

    with tempfile.TemporaryDirectory(prefix="facets-npmaudit-corpus-") as scratch:
        target = _materialized(
            _FIXTURES / spec.directory / "fixture_repo", Path(scratch)
        )
        audit = json.loads(
            (_FIXTURES / spec.directory / "npm.json").read_text(encoding="utf-8")
        )
        report = NpmAuditScanner.convert_results(
            audit, target, lock_file=target / "package-lock.json"
        )
        yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_cdk_nag(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    import csv

    from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
        _reporting_descriptor_for,
    )
    from automated_security_helper.utils.cdk_nag_wrapper import (
        _NagFinding,
        build_nag_results,
    )
    from automated_security_helper.utils.cfn_template_model import (
        get_model_from_template_text,
    )

    results_dir = _FIXTURES / spec.directory / "test.yaml_cdk_nag_results"
    pairs = (
        ("AwsSolutions-test-yaml-NagReport.csv", "test-yaml.template.json"),
        (
            "AwsSolutions-test-yaml-cfn-NagReport.csv",
            "cfn-and-python-test-yaml.template.json",
        ),
    )
    for report_name, template_name in pairs:
        pack = report_name.split("-")[0]
        with (results_dir / report_name).open(encoding="utf-8", newline="") as handle:
            findings = [
                _NagFinding(
                    rule_id=row["Rule ID"],
                    resource_id=row["Resource ID"],
                    compliance=row["Compliance"],
                    exception_reason=row["Exception Reason"],
                    rule_level=row["Rule Level"],
                    rule_info=row["Rule Info"],
                    pack=pack,
                )
                for row in csv.DictReader(handle)
            ]
        template_path = results_dir / template_name
        template_text = template_path.read_text(encoding="utf-8")
        model = get_model_from_template_text(template_text, template_path)
        assert model is not None, template_name
        per_pack = build_nag_results(
            {pack: findings},
            model,
            template_path,
            template_text.splitlines(),
        )
        nag_results = [r for results in per_pack.values() for r in results]
        # The run the scanner writes carries one descriptor per rule, which is
        # where the rule's help link lives; build it the way scan() does.
        representatives: dict[Any, Result] = {}
        for result in nag_results:
            representatives.setdefault(result.ruleId, result)
        rules = [
            _reporting_descriptor_for(rep, tool_name="cdk-nag", tool_type="IAC")
            for rep in representatives.values()
        ]
        yield _report_with_rules("ash-cdk-nag-wrapper", rules), nag_results


#: Registered preps: native, non-SARIF or adapter-normalized fixtures through
#: the adapter's own pure function. A prep never runs a tool.
_PREPS: Mapping[
    str, Callable[[CorpusSpec], Iterator[tuple[SarifReport, list[Result]]]]
] = {
    "actionlint": _prep_actionlint,
    "betterleaks": _prep_betterleaks,
    "cdk-nag": _prep_cdk_nag,
    "cfn-guard": _prep_cfn_guard,
    "cfn-lint": _prep_cfn_lint,
    "cfn-nag": _prep_cfn_nag,
    "checkov": _prep_checkov,
    "detect-secrets": _prep_detect_secrets,
    "ferret-scan": _prep_ferret_scan,
    "gitleaks": _prep_gitleaks,
    "grype": _prep_grype,
    "guarddog": _prep_guarddog,
    "npm-audit": _prep_npm_audit,
    "snyk-code": _prep_snyk_code,
    "trivy": _prep_trivy,
}


def _results_with_runs(
    spec: CorpusSpec, fixtures_root: Path = _FIXTURES
) -> Iterator[tuple[Any, Result]]:
    """(run or None, result) for every result of the scanner's corpus.

    ``fixtures_root`` roots the SARIF globs only (a planted control points it at
    a scratch directory); a registered prep always reads the committed corpus.
    """
    if spec.prep is not None:
        for report, results in _PREPS[spec.prep](spec):
            run = report.runs[0] if report.runs else None
            for result in results:
                yield run, result
        return
    for pattern in spec.sarif:
        for path in sorted((fixtures_root / spec.directory).glob(pattern)):
            report = _load_sarif(path)
            for run in report.runs or []:
                for result in run.results or []:
                    yield run, result


@functools.lru_cache(maxsize=None)
def observed_frame(
    name: str, spec: Optional[CorpusSpec], fixtures_root: Path = _FIXTURES
) -> Optional[dict[str, tuple[int, int]]]:
    """Per facet (non_null_count, total_results) over the scanner's corpus, or
    None when the scanner has no corpus (no spec, or no readable fixture/prep).

    Cached: the gate, the transcript comparison and the named-gap rows each
    read the same corpus, and a prep converts every fixture it holds. Callers
    read the returned mapping and never change it.
    """
    if spec is None or (not spec.sarif and spec.prep is None):
        return None
    tool_type = SCANNER_TOOL_TYPES[name]
    flats = [
        FlatVulnerability.from_sarif_result(result, name, tool_type, run)
        for run, result in _results_with_runs(spec, fixtures_root)
    ]
    return observed_counts(flats)


def _hint(name: str) -> str:
    spec = CORPORA.get(name)
    if spec is None:
        return _NO_FIXTURE_DIRECTORY.get(name, "no committed fixture")
    return spec.missing or (
        f"tests/test_data/scanners/{spec.directory} holds no result for it"
    )


def verdict_rows(
    classes: list[type] | None = None,
) -> list[Verdict]:
    """Every (scanner, facet) verdict over the committed corpus, in registry order."""
    rows: list[Verdict] = []
    for cls in classes if classes is not None else SCANNER_CLASSES:
        name = _name(cls)
        spec = CORPORA.get(name)
        frame = observed_frame(name, spec)
        for facet, state in _declared(cls).items():
            observed = None if frame is None else frame.get(facet)
            rows.append(judge(name, facet, state, observed, corpus_hint=_hint(name)))
    return rows


# --------------------------------------------------------------------------
# The gate.
# --------------------------------------------------------------------------


def test_the_gate_carries_no_waiver_but_the_register() -> None:
    """Contract: register redeclaration is the only waiver.

    The gate's own source has no skip, xfail, allowlist or suppression list of
    cells; the module-level tables are corpus locations and observation maps,
    never exemptions. A cell the gate refuses is fixed or redeclared.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    # Only the text above this test is read, so the needles below (which sit in
    # this test's own body) never match themselves.
    body = source.split("def test_the_gate_carries_no_waiver_but_the_register")[0]
    for needle in ("pytest." + "skip(", "pytest." + "xfail(", "mark." + "xfail"):
        assert needle not in body, f"the gate must not waive cells: {needle}"


def test_the_registry_and_the_corpus_table_agree() -> None:
    assert not _REMAINING_LOAD_ERRORS, _REMAINING_LOAD_ERRORS
    names = {_name(cls) for cls in SCANNER_CLASSES}
    assert len(SCANNER_CLASSES) == 23, sorted(c.__name__ for c in SCANNER_CLASSES)
    assert names == set(CORPORA) == set(SCANNER_TOOL_TYPES), (
        f"registry {sorted(names)} / corpus table {sorted(CORPORA)}: a scanner "
        "needs a CORPORA row (a corpus, or None with the fixture to author)"
    )
    for name, spec in CORPORA.items():
        if spec is None:
            assert name in _NO_FIXTURE_DIRECTORY, name
            continue
        assert (_FIXTURES / spec.directory).is_dir(), f"{name}: {spec.directory}"
        if not spec.sarif and spec.prep is None:
            assert spec.missing, f"{name}: a corpus-less spec names what to author"


def test_discovery_does_not_depend_on_which_tier_declares_a_scanner() -> None:
    """The gate reads every plugin package's ``ASH_SCANNERS`` the same way.

    Core (ash_builtin), the alpha ash_*_plugins packages and any package an SDK
    plugin ships are one population here: the gate names no tier, and a scanner
    is in or out by declaring itself, not by where it lives. The registered set
    must equal the union of every package's list, and must span more than one
    package so the check is not satisfied by a single tier.
    """
    declared: set[type] = set()
    packages_with_scanners: set[str] = set()
    for info in pkgutil.iter_modules(plugin_modules.__path__):
        if not info.ispkg:
            continue
        package = importlib.import_module(f"{plugin_modules.__name__}.{info.name}")
        found = list(getattr(package, "ASH_SCANNERS", []))
        if found:
            packages_with_scanners.add(info.name)
        declared.update(found)
    assert set(SCANNER_CLASSES) == declared
    assert len(packages_with_scanners) >= 2, packages_with_scanners
    # No scanner is looked up by the name of a tier or a package.
    body = (
        Path(__file__)
        .read_text(encoding="utf-8")
        .split("def test_discovery_does_not_depend")[0]
    )
    for needle in ("startswith(" + '"ash_', "== " + '"ash_builtin"'):
        assert needle not in body, needle


def test_the_scanners_read_from_captures_are_observed() -> None:
    """The scanners whose cells were redeclared unread are observed now, over a
    capture of the tool. snyk-code is not among them: its only committed SARIF is
    authored, so it has no corpus and its cells stay unconfirmed."""
    assert observed_frame("snyk-code", CORPORA["snyk-code"]) is None
    for name in ("grype", "ferret-scan"):
        frame = observed_frame(name, CORPORA[name])
        assert frame is not None, name
        assert frame["rule_id"][1] > 0 and frame["rule_id"][0] == frame["rule_id"][1]
        assert frame["file_path"][0] > 0 and frame["message"][0] > 0, name
    assert observed_frame("grype", CORPORA["grype"])["fingerprints"][0] > 0
    assert observed_frame("ferret-scan", CORPORA["ferret-scan"])["fingerprints"][0] == 0


def test_the_corpus_is_not_vacuous() -> None:
    """A gate over an empty universe passes everything; refuse that."""
    with_corpus = {}
    for cls in SCANNER_CLASSES:
        frame = observed_frame(_name(cls), CORPORA.get(_name(cls)))
        if frame is not None:
            with_corpus[_name(cls)] = frame["rule_id"][1]
    assert len(with_corpus) >= 10, with_corpus
    assert all(total > 0 for total in with_corpus.values()), with_corpus
    # Known-populated cells (must-observe controls): the observation really
    # reads columns, so a dead read cannot pass the gate by emptiness alone.
    gitleaks = observed_frame("gitleaks", CORPORA["gitleaks"])
    assert gitleaks is not None
    assert gitleaks["rule_id"][0] > 0 and gitleaks["file_path"][0] > 0
    assert gitleaks["line_range"][0] > 0 and gitleaks["severity"][0] > 0


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=_name)
def test_declared_facets_agree_with_the_observed_corpus(cls: type) -> None:
    failures = [v for v in verdict_rows([cls]) if v.outcome == "FAIL"]
    assert not failures, "\n".join(
        f"[{v.scanner}.{v.facet}] {v.detail}" for v in failures
    )


# --------------------------------------------------------------------------
# Planted controls: every drift class over synthetic corpora.
# --------------------------------------------------------------------------


def test_planted_a_mapped_facet_with_an_empty_column_fails() -> None:
    verdict = judge("planted", "file_path", FacetState.MAPPED, (0, 4))
    assert verdict.outcome == "FAIL"
    assert "planted.file_path" in verdict.detail and "empty" in verdict.detail


def test_planted_a_mapped_facet_with_no_corpus_names_the_missing_fixture() -> None:
    verdict = judge(
        "planted",
        "rule_id",
        FacetState.MAPPED,
        None,
        corpus_hint="author planted/captured/out.sarif",
    )
    assert verdict.outcome == "FAIL"
    assert "author planted/captured/out.sarif" in verdict.detail
    empty = judge("planted", "rule_id", FacetState.MAPPED, (0, 0))
    assert empty.outcome == "FAIL" and "hold no results" in empty.detail


def test_planted_an_na_facet_over_a_populated_column_fails() -> None:
    verdict = judge("planted", "resource_id", FacetState.NA, (3, 4))
    assert verdict.outcome == "FAIL" and "populated" in verdict.detail


def test_planted_a_dropped_facet_over_a_populated_column_fails() -> None:
    verdict = judge("planted", "references", FacetState.DROPPED, (1, 4))
    assert verdict.outcome == "FAIL" and "redeclare it MAPPED" in verdict.detail


@pytest.mark.parametrize(
    "state,observed",
    [
        (FacetState.MAPPED, (2, 4)),
        (FacetState.NA, (0, 4)),
        (FacetState.NA, None),
        (FacetState.DROPPED, (0, 4)),
        (FacetState.DROPPED, None),
    ],
    ids=[
        "mapped-populated",
        "na-empty",
        "na-no-corpus",
        "dropped-empty",
        "dropped-no-corpus",
    ],
)
def test_planted_legitimate_cells_pass(
    state: FacetState, observed: Optional[tuple[int, int]]
) -> None:
    assert judge("planted", "tags", state, observed).outcome == "ok"


@pytest.mark.parametrize("observed", [(0, 4), None], ids=["empty", "no-corpus"])
def test_planted_an_unconfirmed_facet_over_no_observation_is_owed(
    observed: Optional[tuple[int, int]],
) -> None:
    """UNCONFIRMED over an empty or absent column is a fixture owed: nothing
    has been read, so the cell is listed, never failed and never passed."""
    verdict = judge("planted", "rule_id", FacetState.UNCONFIRMED, observed)
    assert verdict.outcome == "owed", verdict.detail
    assert "fixture owed" in verdict.detail


def test_planted_an_unconfirmed_facet_over_a_populated_column_fails() -> None:
    """A populated column is a read: the cell is settled (redeclare it MAPPED)
    or contaminated (fix the adapter). Leaving it UNCONFIRMED would let a value
    reach the flat row from a committed fixture with no check."""
    verdict = judge("planted", "rule_id", FacetState.UNCONFIRMED, (3, 4))
    assert verdict.outcome == "FAIL", verdict.detail
    assert "planted.rule_id declared unconfirmed" in verdict.detail
    assert "settled or contaminated" in verdict.detail
    assert "redeclare" in verdict.detail and "fix the adapter" in verdict.detail


@pytest.mark.parametrize("facet", ["column", "remediation_text", "extras"])
def test_planted_an_unconfirmed_facet_on_an_excluded_column_is_still_owed(
    facet: str,
) -> None:
    """The excluded columns cannot be observed, so the owed list is the only
    place an UNCONFIRMED cell on them is visible: it must not read "excluded"."""
    verdict = judge("planted", facet, FacetState.UNCONFIRMED, None)
    assert verdict.outcome == "owed", verdict.outcome
    assert judge("planted", facet, FacetState.MAPPED, None).outcome == "excluded"


def test_the_owed_fixtures_are_exactly_the_registers_unconfirmed_cells() -> None:
    declared = {
        (_name(cls), facet)
        for cls in SCANNER_CLASSES
        for facet in FACET_NAMES
        if getattr(vars(cls).get(SCANNER_FACETS_ATTR), facet).state
        is FacetState.UNCONFIRMED
    }
    assert declared, "the register declares no UNCONFIRMED cell: the control is dead"
    owed = {(v.scanner, v.facet) for v in verdict_rows() if v.outcome == "owed"}
    assert owed == declared, (
        f"owed but not declared: {sorted(owed - declared)}; "
        f"declared but not owed: {sorted(declared - owed)}"
    )


def test_no_cell_is_the_unread_state_in_disguise() -> None:
    """Only UNCONFIRMED means nobody read a run. A MAPPED, DROPPED or N/A cell
    whose reason says it is unconfirmed, or that no output was read, claims a
    state the evidence does not back; it is declared UNCONFIRMED instead."""
    cells = [
        (f"{_name(cls)}.{facet}", getattr(vars(cls).get(SCANNER_FACETS_ATTR), facet))
        for cls in SCANNER_CLASSES
        for facet in FACET_NAMES
    ]
    stretched = _unread_in_disguise(cells)
    assert not stretched, (
        "declared a settled state but worded as unread: redeclare these "
        "UNCONFIRMED, or settle them with the evidence -- " + ", ".join(stretched)
    )


def _unread_in_disguise(cells: list[tuple[str, FacetDecl]]) -> list[str]:
    """The cells that are not UNCONFIRMED yet say, anywhere in the reason, that
    nobody read a run (case-insensitive), in every settled state."""
    found = []
    for label, cell in cells:
        reason = (cell.reason or "").lower()
        if cell.state is not FacetState.UNCONFIRMED and (
            "unconfirmed" in reason or "output not read" in reason
        ):
            found.append(f"{label} ({cell.state.value})")
    return found


def test_the_disguise_check_flags_a_planted_cell_of_every_state() -> None:
    """Must-flag and must-not-flag controls through the real check."""
    worded = "mid-sentence, Unconfirmed against a real tool run"
    planted = [
        (f"p.{state.value}", FacetDecl(state=state, native_field="f", reason=worded))
        for state in (FacetState.MAPPED, FacetState.DROPPED, FacetState.NA)
    ]
    assert len(_unread_in_disguise(planted)) == 3
    honest = [
        ("p.unconfirmed", FacetDecl(state=FacetState.UNCONFIRMED, reason=worded)),
        ("p.na", FacetDecl(state=FacetState.NA, reason="the tool cannot carry it")),
    ]
    assert _unread_in_disguise(honest) == []


def test_planted_an_excluded_facet_is_never_judged() -> None:
    for facet in ("column", "remediation_text", "extras"):
        assert judge("planted", facet, FacetState.MAPPED, None).outcome == "excluded"


def test_every_failure_names_the_cell_and_both_exits() -> None:
    verdicts = [
        judge("s", "file_path", FacetState.MAPPED, (0, 2)),
        judge("s", "file_path", FacetState.MAPPED, None),
        judge("s", "resource_id", FacetState.NA, (1, 2)),
        judge("s", "references", FacetState.DROPPED, (1, 2)),
    ]
    for verdict in verdicts:
        assert verdict.outcome == "FAIL"
        assert f"s.{verdict.facet} declared {verdict.state}" in verdict.detail
        assert "fix the adapter or the fixture" in verdict.detail
        assert "redeclare the cell" in verdict.detail


def _planted_sarif(*, with_location: bool, with_tags: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": "PLANTED-1",
        "level": "error",
        "message": {"text": "a planted finding"},
    }
    if with_location:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3},
                }
            }
        ]
    if with_tags:
        result["properties"] = {"tags": ["planted"]}
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "planted"}}, "results": [result]}],
    }


def test_planted_a_fixture_with_the_mapped_field_removed_is_flagged(
    tmp_path: Path,
) -> None:
    """Must-flag through the real observation path: a fixture copy with the
    native location removed reads empty file_path and line_range, so a MAPPED
    declaration over it fails; the intact copy passes.

    The counts come from ``observed_frame``, which reads the columns through
    ``FACET_COLUMNS``: a control that recomputed one column by hand would stay
    green when the column mapping of the real gate was mis-wired.
    """
    for with_location, expected in ((True, "ok"), (False, "FAIL")):
        directory = tmp_path / f"planted-{with_location}"
        directory.mkdir()
        (directory / "planted.sarif").write_text(
            json.dumps(_planted_sarif(with_location=with_location))
        )
        spec = CorpusSpec(directory.name, sarif=("planted.sarif",))
        frame = observed_frame("bandit", spec, fixtures_root=tmp_path)
        assert frame is not None
        for facet in ("file_path", "line_range"):
            verdict = judge("planted", facet, FacetState.MAPPED, frame[facet])
            assert verdict.outcome == expected, (facet, verdict.detail)


def test_planted_a_result_with_only_a_rule_id_reads_empty_but_for_the_defaults(
    tmp_path: Path,
) -> None:
    """A result that declares nothing but its rule id and message populates
    exactly the facets the flat row fills by default, through the real frame.

    ``severity`` is one of them (a result with no level reads MEDIUM), so a
    MAPPED severity cell is observed as populated even when the tool wrote no
    level: that cell is held by the fixture content, not by this column. Every
    other facet must read empty, so a default that starts to populate one of
    them (a fix_available=False, a placeholder path) shows up here first.
    """
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "planted"}},
                "results": [
                    {"ruleId": "PLANTED-1", "message": {"text": "a finding"}},
                ],
            }
        ],
    }
    directory = tmp_path / "only-rule-id"
    directory.mkdir()
    (directory / "planted.sarif").write_text(json.dumps(sarif))
    frame = observed_frame(
        "bandit",
        CorpusSpec(directory.name, sarif=("planted.sarif",)),
        fixtures_root=tmp_path,
    )
    assert frame is not None
    populated = {facet for facet, (count, _total) in frame.items() if count}
    assert populated == {"rule_id", "severity", "message"}, populated
    assert all(total == 1 for _count, total in frame.values())


def test_a_text_column_of_another_type_is_unreadable_not_empty() -> None:
    """The contamination direction must not fail open on a type change."""
    assert text_present("a value") is True
    assert text_present("  ") is False
    assert text_present(None) is False
    for value in (0, 1, False, ["a"], {"a": 1}, b"bytes"):
        with pytest.raises(TypeError, match="not str or None"):
            text_present(value)


def test_judge_refuses_a_state_it_does_not_judge() -> None:
    """The next FacetState member must be judged on purpose, never passed."""
    for state in FacetState:
        for observed in ((1, 2), (0, 2), None):
            judge("planted", "tags", state, observed)  # no member is refused
    with pytest.raises(AssertionError, match="no judgment"):
        # an object that is not one of the four members, as a fifth would be
        judge("planted", "tags", SimpleNamespace(value="a-new-state"), (1, 2))  # type: ignore[arg-type]


def test_planted_a_legitimate_na_cell_over_the_real_corpus_passes() -> None:
    """Must-not-flag over real fixtures: some N/A cell sits over a non-empty
    corpus whose column is empty, and the join passes it."""
    legitimate = [
        v
        for v in verdict_rows()
        if v.state == FacetState.NA.value and v.total and v.non_null == 0
    ]
    assert legitimate, "no N/A cell over a non-empty corpus: the control is vacuous"
    assert all(v.outcome == "ok" for v in legitimate)


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=_name)
def test_the_transcripts_observe_exactly_what_the_corpus_table_observes(
    cls: type,
) -> None:
    """The upgrade of the loose fixtures into transcripts lost no corpus and added none.

    ``ash plugin verify`` judges the facet cells over transcripts
    (core/plugin_conformance.py); this gate judges them over the CORPORA table. Until
    the table is retired the two must observe the same counts for every scanner, or the
    promotion bar and the PR gate would disagree about one register row.
    """
    from automated_security_helper.core.plugin_conformance import (
        discover_transcript_files,
        observed_frame as transcript_frame,
        transcripts_of,
    )

    name = _name(cls)
    mine = transcripts_of(name, discover_transcript_files(_FIXTURES))
    got = transcript_frame(name, mine) if mine else None
    assert got == observed_frame(name, CORPORA.get(name))


#: MAPPED cells that only a historical recording fills today, by scanner. ``ash plugin
#: verify`` reads each as red until the scanner is re-recorded at its pin with a
#: recording that carries it; the entry is then deleted (the test below fails when a gap
#: closes, so the table cannot go stale). Trivy's current recording is the terraform
#: misconfiguration run, which has no package and no fixed version; its
#: package-bearing runs are 0.69.3 and 0.75.0.
_ONLY_A_HISTORICAL_RECORDING_FILLS: dict[str, frozenset[str]] = {
    "trivy": frozenset(
        {
            "fix_available",
            "package_name",
            "package_version",
            "package_path",
            "taxonomy_cve",
        }
    ),
    "trivy-repo": frozenset(
        {
            "fix_available",
            "package_name",
            "package_version",
            "package_path",
            "taxonomy_cve",
        }
    ),
}


@pytest.mark.parametrize("cls", SCANNER_CLASSES, ids=_name)
def test_the_current_recordings_alone_carry_every_mapped_cell_but_the_named_gaps(
    cls: type,
) -> None:
    """``ash plugin verify`` judges a MAPPED cell over current recordings only, so a
    historical recording of an older release cannot keep a cell green after the pinned
    tool stops filling it. For a scanner that has a current, readable recording, the
    MAPPED cells the current recordings alone leave empty are exactly the named gaps."""
    from automated_security_helper.core.plugin_conformance import (
        discover_transcript_files,
        observed_frame as transcript_frame,
        transcripts_of,
    )

    name = _name(cls)
    mine = transcripts_of(name, discover_transcript_files(_FIXTURES))
    current = transcript_frame(name, mine, current_only=True)
    if current is None:
        return
    declared = vars(cls).get(SCANNER_FACETS_ATTR)
    empty = set()
    for facet in FACET_NAMES:
        state = getattr(declared, facet).state
        if state is not FacetState.MAPPED:
            continue
        if judge(name, facet, state, current.get(facet)).outcome == "FAIL":
            empty.add(facet)
    assert empty == _ONLY_A_HISTORICAL_RECORDING_FILLS.get(name, frozenset())


def test_the_current_only_reading_is_not_vacuous() -> None:
    """Some scanner has both a current and a historical recording, and some scanner has a
    current recording that reads as results; otherwise the test above checks nothing."""
    from automated_security_helper.core.plugin_conformance import (
        discover_transcript_files,
        transcripts_of,
    )

    files = discover_transcript_files(_FIXTURES)
    mixed = [
        _name(cls)
        for cls in SCANNER_CLASSES
        if {t.retention for _b, t in transcripts_of(_name(cls), files)}
        == {"current", "historical"}
    ]
    assert mixed, "no scanner keeps both a current and a historical recording"


if __name__ == "__main__":  # pragma: no cover
    # Prints the gate's whole verdict table (TSV: scanner, facet, declared
    # state, non_null/total, outcome, detail) for triage and for reports.
    for _verdict in verdict_rows():
        print(_verdict.row())
