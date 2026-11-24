# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The register consistency gate: declared facets against observed columns.

The facets register (automated_security_helper/base/scanner_facets.py) says,
per scanner and facet, whether the native output maps (MAPPED), could map but
is discarded today (DROPPED), or cannot be there (N/A). The conformance rows
beside this module prove one cell at a time that a declaration is not a lie
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

import importlib
import json
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional

import pytest

from automated_security_helper import plugin_modules
from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules import ash_builtin
from automated_security_helper.schemas.sarif_schema_model import Result, SarifReport
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES
from automated_security_helper.utils.scanner_tool_types import _class_config_name

pytestmark = pytest.mark.unit

_REMAINING_LOAD_ERRORS = ash_builtin.retry_failed_plugin_groups()

_FIXTURES = Path(__file__).resolve().parents[2] / "test_data" / "scanners"


# --------------------------------------------------------------------------
# The facet -> observed-column map (GC-1). Total over FACET_NAMES.
# --------------------------------------------------------------------------


def _text(value: Any) -> bool:
    return isinstance(value, str) and value.strip() not in ("", "[]", "{}", "null")


def _present(value: Any) -> bool:
    return value is not None


@dataclass(frozen=True)
class Observation:
    """How one facet is read off a flat row.

    ``columns`` are the FlatVulnerability attributes read; ``populated`` is the
    predicate over their values (in column order). ``excluded`` is the declared
    v1 exclusion reason for a facet with no flat column.
    """

    columns: tuple[str, ...] = ()
    populated: Optional[Callable[..., bool]] = None
    excluded: Optional[str] = None


FACET_COLUMNS: Mapping[str, Observation] = {
    "rule_id": Observation(("rule_id",), _text),
    "severity": Observation(("severity",), _text),
    "file_path": Observation(("file_path",), _text),
    "line_range": Observation(
        ("line_start", "line_end"), lambda start, end: _present(start) or _present(end)
    ),
    "column": Observation(
        excluded="the flat row has no column field: the start column is read "
        "only into the finding identity, so it is observed nowhere (G10 shape)"
    ),
    "message": Observation(("description",), _text),
    "resource_id": Observation(("resource_id",), _text),
    "resource_type": Observation(("resource_type",), _text),
    "package_name": Observation(("package_name",), _text),
    "package_version": Observation(("package_version",), _text),
    "package_path": Observation(("package_path",), _text),
    "taxonomy_cve": Observation(("cve_id",), _text),
    "taxonomy_cwe": Observation(("cwe_id",), _text),
    # A boolean observation: the id is keyed by a scanner fingerprint.
    "fingerprints": Observation(("has_fingerprint_identity",), bool),
    # False is a written value (the adapter said "no fix"); only None is empty.
    "fix_available": Observation(("fix_available",), _present),
    "remediation_text": Observation(
        excluded="no flat column: remediation text lives only in the SARIF "
        "property bag (G10; add property-bag observation as its own unit)"
    ),
    "snippet": Observation(("code_snippet",), _text),
    "references": Observation(("references",), _text),
    "tags": Observation(("tags",), _text),
    "extras": Observation(
        excluded="no flat column: extras are the property bag itself (G10; "
        "add property-bag observation as its own unit)"
    ),
}


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

#: The two legal exits, named in every failure so the maintainer never has to
#: guess what "fix" means. There is no third (no skip list; see the module
#: docstring's waiver contract).
_EXITS = (
    "Two exits: (1) fix the adapter or the fixture so the observed column "
    "matches the declaration, or (2) redeclare the cell in the scanner's own "
    "register row (the `facets` class attribute) with its reason; that edit "
    "is the reviewed waiver and the only one."
)


@dataclass(frozen=True)
class Verdict:
    scanner: str
    facet: str
    state: str
    non_null: Optional[int]
    total: Optional[int]
    outcome: str  # "ok" | "FAIL" | "excluded"
    detail: str

    def row(self) -> str:
        counted = "no-corpus" if self.total is None else f"{self.non_null}/{self.total}"
        return (
            f"{self.scanner}\t{self.facet}\t{self.state}\t{counted}\t"
            f"{self.outcome}\t{self.detail}"
        )


def judge(
    scanner: str,
    facet: str,
    state: FacetState,
    observed: Optional[tuple[int, int]],
    *,
    corpus_hint: str = "",
) -> Verdict:
    """The verdict for one cell. ``observed`` is (non_null_count, total_results)
    or None when the scanner has no corpus at all."""
    if FACET_COLUMNS[facet].excluded is not None:
        return Verdict(scanner, facet, state.value, None, None, "excluded", "G10")
    non_null, total = observed if observed is not None else (None, None)
    populated = bool(non_null)
    cell = f"{scanner}.{facet} declared {state.value}"
    if state is FacetState.MAPPED:
        if observed is None or not total:
            why = (
                "has no corpus to observe: "
                + (corpus_hint or "no committed fixture and no registered prep")
                if observed is None
                else f"its fixtures hold no results ({corpus_hint or 'empty corpus'})"
            )
            return Verdict(
                scanner,
                facet,
                state.value,
                non_null,
                total,
                "FAIL",
                f"{cell} but the scanner {why}. Name the missing fixture "
                f"(author it) or register its prep. {_EXITS}",
            )
        if not populated:
            return Verdict(
                scanner,
                facet,
                state.value,
                non_null,
                total,
                "FAIL",
                f"{cell} but the observed column is empty across the corpus "
                f"(0 of {total} results): the tool's output moved or an adapter "
                f"regression dropped the mapping. {_EXITS}",
            )
    elif state is FacetState.NA and populated:
        return Verdict(
            scanner,
            facet,
            state.value,
            non_null,
            total,
            "FAIL",
            f"{cell} (cannot be present) but the observed column is populated "
            f"({non_null} of {total} results): a value reached a column the "
            f"register says is impossible. {_EXITS}",
        )
    elif state is FacetState.DROPPED and populated:
        return Verdict(
            scanner,
            facet,
            state.value,
            non_null,
            total,
            "FAIL",
            f"{cell} (discarded today) but the observed column is populated "
            f"({non_null} of {total} results): the cell is out of date, "
            f"redeclare it MAPPED with its native field. {_EXITS}",
        )
    return Verdict(scanner, facet, state.value, non_null, total, "ok", "")


# --------------------------------------------------------------------------
# The corpus: registered scanners, their fixtures, the observed frame (GC-1).
# --------------------------------------------------------------------------


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
    "actionlint": CorpusSpec(
        "actionlint",
        missing="actionlint's committed output is native JSON (actionlint/"
        "actionlint-1.7.12-*.json) and no prep converts it; author a "
        "SARIF-shaped capture of build_sarif's output or register a prep",
    ),
    "bandit": CorpusSpec("bandit", sarif=("captured/*.sarif",)),
    "betterleaks": CorpusSpec("betterleaks", sarif=("captured/*.sarif",)),
    "cdk-nag": CorpusSpec(
        "cdk",
        missing="cdk-nag's committed output is the NagReport CSV and no prep "
        "converts it; author a SARIF capture of the scanner's own report",
    ),
    "cfn-guard": CorpusSpec(
        "cfn_lint_guard", sarif=("captured/cfn-guard-*.sarif",), prep="cfn-guard"
    ),
    "cfn-lint": CorpusSpec(
        "cfn_lint_guard", sarif=("captured/cfn-lint-*.sarif",), prep="cfn-lint"
    ),
    "cfn-nag": CorpusSpec(
        "cfn_nag",
        missing="cfn-nag's committed output is native JSON "
        "(cfn_nag/src.test.yaml.json) and no SARIF capture is committed "
        "(M0-FINDINGS.md (b): the tool could not be run to a real result)",
    ),
    "checkov": CorpusSpec(
        "checkov",
        missing="checkov's committed output is native JSON (checkov/"
        "src.test.yaml.json) and no prep converts it; author a SARIF capture "
        "of the scanner's own report or register a prep",
    ),
    "detect-secrets": None,
    "ferret-scan": CorpusSpec(
        "ferret-scan",
        missing="ferret-scan commits only its input samples (sample.txt, a "
        ".docx), no captured output",
    ),
    "gitleaks": CorpusSpec("gitleaks", sarif=("gitleaks-*.sarif",)),
    "grype": CorpusSpec(
        "grype",
        missing="grype commits native JSON only (grype/grype.src.json); the "
        "SARIF is rendered inside test_grype_fix_available_conformance.py, "
        "not committed. Commit a `grype -o sarif` capture or register a prep",
    ),
    "guarddog": CorpusSpec("guarddog", prep="guarddog"),
    "hadolint": CorpusSpec("hadolint", sarif=("captured/*.sarif",)),
    "npm-audit": CorpusSpec(
        "npmaudit",
        missing="npm-audit's committed output is raw `npm audit` / yarn / pnpm "
        "JSON and the converter is an instance method that needs a lockfile "
        "tree; author a SARIF capture of the scanner's own report",
    ),
    "opengrep": CorpusSpec("opengrep", sarif=("captured/*.sarif",)),
    "semgrep": CorpusSpec(
        "semgrep",
        missing="semgrep commits native JSON only (semgrep/semgrep.src.json); "
        "commit a `semgrep --sarif` capture",
    ),
    "snyk-code": None,
    "syft": CorpusSpec(
        "syft",
        missing="syft commits its native SBOM JSON only (syft/syft.src.json); "
        "commit a capture of the scanner's SARIF report",
    ),
    "trivy": CorpusSpec("trivy", sarif=("*.sarif", "captured/*.sarif")),
    "trivy-repo": CorpusSpec("trivy", sarif=("*.sarif", "captured/*.sarif")),
    "zizmor": CorpusSpec("zizmor", sarif=("*.sarif",)),
}

#: Why a scanner with no CorpusSpec has none (named, not authored).
_NO_FIXTURE_DIRECTORY = {
    "detect-secrets": "no tests/test_data/scanners/detect_secrets directory; "
    "commit a captured detect-secrets result",
    "snyk-code": "no tests/test_data/scanners/snyk directory; commit a "
    "captured `snyk code test --sarif` result (needs a licensed run)",
}


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
    )

    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            report = _load_sarif(path)
            # normalize_report reads no instance state: it locates results,
            # maps severities and sorts rules in place.
            CfnLintScanner.normalize_report(None, report)  # type: ignore[arg-type]
            yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_guarddog(spec: CorpusSpec) -> Iterator[tuple[SarifReport, list[Result]]]:
    from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
        convert_guarddog_scan_result,
    )

    for path in sorted((_FIXTURES / spec.directory / "captured").glob("scan_*.json")):
        ecosystem = path.stem.split("_")[1]
        document = json.loads(path.read_text(encoding="utf-8"))
        converted = convert_guarddog_scan_result(
            document, uri_prefix="", ecosystem=ecosystem, include_capabilities=True
        )
        report = SarifReport.model_validate({"version": "2.1.0", "runs": []})
        yield report, list(converted.results)


#: Registered preps: native, non-SARIF or adapter-normalized fixtures through
#: the adapter's own pure function. A prep never runs a tool.
_PREPS: Mapping[str, Callable[[CorpusSpec], Iterator[tuple[SarifReport, list[Result]]]]] = {
    "cfn-guard": _prep_cfn_guard,
    "cfn-lint": _prep_cfn_lint,
    "guarddog": _prep_guarddog,
}


def _results_with_runs(
    spec: CorpusSpec,
) -> Iterator[tuple[Any, Result]]:
    """(run or None, result) for every result of the scanner's corpus."""
    if spec.prep is not None:
        for report, results in _PREPS[spec.prep](spec):
            run = report.runs[0] if report.runs else None
            for result in results:
                yield run, result
        return
    for pattern in spec.sarif:
        for path in sorted((_FIXTURES / spec.directory).glob(pattern)):
            report = _load_sarif(path)
            for run in report.runs or []:
                for result in run.results or []:
                    yield run, result


def observed_frame(
    name: str, spec: Optional[CorpusSpec]
) -> Optional[dict[str, tuple[int, int]]]:
    """Per facet (non_null_count, total_results) over the scanner's corpus, or
    None when the scanner has no corpus (no spec, or no readable fixture/prep).
    """
    if spec is None or (not spec.sarif and spec.prep is None):
        return None
    tool_type = SCANNER_TOOL_TYPES[name]
    flats = [
        FlatVulnerability.from_sarif_result(result, name, tool_type, run)
        for run, result in _results_with_runs(spec)
    ]
    counts: dict[str, tuple[int, int]] = {}
    for facet, observation in FACET_COLUMNS.items():
        if observation.excluded is not None:
            continue
        populated = 0
        for flat in flats:
            values = [getattr(flat, column) for column in observation.columns]
            if observation.populated(*values):  # type: ignore[misc]
                populated += 1
        counts[facet] = (populated, len(flats))
    return counts


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
    assert len(SCANNER_CLASSES) == 22, sorted(c.__name__ for c in SCANNER_CLASSES)
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
    ids=["mapped-populated", "na-empty", "na-no-corpus", "dropped-empty", "dropped-no-corpus"],
)
def test_planted_legitimate_cells_pass(
    state: FacetState, observed: Optional[tuple[int, int]]
) -> None:
    assert judge("planted", "tags", state, observed).outcome == "ok"


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
    native location removed reads empty file_path/line_range, so a MAPPED
    declaration over it fails; the intact copy passes."""
    for with_location, expected in ((True, "ok"), (False, "FAIL")):
        path = tmp_path / f"planted-{with_location}.sarif"
        path.write_text(json.dumps(_planted_sarif(with_location=with_location)))
        report = _load_sarif(path)
        flats = [
            FlatVulnerability.from_sarif_result(r, "bandit", "SAST", run)
            for run in report.runs or []
            for r in run.results or []
        ]
        non_null = sum(1 for f in flats if _text(f.file_path))
        verdict = judge("planted", "file_path", FacetState.MAPPED, (non_null, len(flats)))
        assert verdict.outcome == expected, verdict.detail


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


if __name__ == "__main__":  # pragma: no cover
    # Prints the gate's whole verdict table (TSV: scanner, facet, declared
    # state, non_null/total, outcome, detail) for triage and for reports.
    for _verdict in verdict_rows():
        print(_verdict.row())
