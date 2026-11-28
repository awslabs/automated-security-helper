# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The conformance harness behind ``ash plugin verify``: the promotion bar, runnable.

Promotion of a scanner from ``alpha`` to ``supported`` is a one-line manifest change
gated on five things. This module evaluates each as a *row* over a scanner's manifest
and its committed transcripts, with no tool run and no network:

1. **Facets over transcripts.** The scanner's recorded transcripts are sound (bytes
   match their digests), fresh (stamped with the pin the manifest declares now), and
   every facet cell of the register agrees with what the transcripts observably carry
   (declared-mapped observed non-empty, declared-N/A empty), judged by
   :func:`~automated_security_helper.base.facet_conformance.judge`, the same function
   the register consistency gate uses. A cell declared UNCONFIRMED is a fixture owed
   and reddens this row: honest-ignorance states must be resolved to promote.
2. **Operational declarations complete.** The operational register row has no
   unconfirmed cell: honest-ignorance states must be resolved to promote.
3. **Live cell.** The live-tool cell is green on every platform the manifest
   declares. The cell itself runs in CI (Phase B); this row only READS its result, so
   without one it is ``NOT_RUN``, never green.
4. **Provisioning.** The tool is pinned (version and SHA-256 per platform), or declared
   user-installed with its prerequisites stated.
5. **Docs.** Documentation generated from the manifest. No generator exists in this
   tree yet, so the row is ``NOT_RUN`` and says why.

A row is ``GREEN``, ``RED`` or ``NOT_RUN``. ``NOT_RUN`` means the row could not be
evaluated here (it is not a pass, and it is not a defect of the plugin). The report's
verdict is ``fail`` if any row is red, ``pass`` only if all five are green, and
``incomplete`` otherwise; ``ash plugin verify`` exits 1, 0 and 3 for them. Demotion is
the same check read the other way, so a ``supported`` scanner is verified the same way.

The harness reaches a plugin through its manifest (``resolve_ref``). The built-in
adapter preps below name the built-in plugin modules by dotted-path STRING, resolved at
run time, so ``core`` imports no plugin module while still depending on those paths
existing (a manifest-named prep, which would drop that dependency, is not built yet). A
scanner class is loaded to read its register rows, the way the kernel will read them: a
class is judged on the rows it declares itself (``vars``), for every register, so a
subclass that inherits a parent's row has declared nothing. Scanner names are one
namespace: a third-party plugin that reuses a shipped scanner's name is judged under the
shipped table (its tool type comes from ``SCANNER_TOOL_TYPES`` before its own row), so
such a plugin needs a name the table does not hold.

A damaged recording is a red row, never a traceback: a results file whose digest fails
is left out of what the facets are judged over, and a file or transcript that cannot be
read or validated is named in row 1 while every other scanner and transcript is still
judged.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional, Sequence

from pydantic import BaseModel, ValidationError

from automated_security_helper.base.facet_conformance import (
    Verdict,
    judge,
    observed_counts,
)
from automated_security_helper.base.plugin_manifest import (
    PluginTier,
    ScannerManifest,
    resolve_ref,
)
from automated_security_helper.base.plugin_provisioning import tool_versions
from automated_security_helper.base.scanner_facets import (
    FACET_NAMES,
    SCANNER_FACETS_ATTR,
    FacetState,
)
from automated_security_helper.base.scanner_operational_facets import (
    LICENSE_NOT_READ,
    OPERATIONAL_FACETS_ATTR,
    RuntimeKind,
    ScannerOperationalFacets,
)
from automated_security_helper.base.tool_transcript import (
    TRANSCRIPT_FILE_NAME,
    ToolTranscript,
    TranscriptFile,
    is_sha256,
    load_transcript_file,
    parse_transcript_file,
    stale_transcripts,
    verify_digests,
)
from automated_security_helper.core.enums import ScanCategory, ScannerToolType
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Result, SarifReport
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES
from automated_security_helper.utils.scanner_tool_types import scanner_tool_type

#: The exit codes of ``ash plugin verify``.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INCOMPLETE = 3


class RowStatus(str, Enum):
    GREEN = "green"
    RED = "red"
    #: The row could not be evaluated here; not a pass.
    NOT_RUN = "not-run"


@dataclass(frozen=True)
class BarRow:
    number: int
    name: str
    status: RowStatus
    #: One sentence per finding (red) or per reason (not-run); empty for green.
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class BarReport:
    scanner: str
    tier: str
    rows: tuple[BarRow, ...]
    #: Per-cell facet verdicts behind row 1 (for ``--json`` and triage).
    verdicts: tuple[Verdict, ...] = field(default=())

    @property
    def verdict(self) -> str:
        if any(row.status is RowStatus.RED for row in self.rows):
            return "fail"
        if all(row.status is RowStatus.GREEN for row in self.rows):
            return "pass"
        return "incomplete"

    @property
    def exit_code(self) -> int:
        return {"pass": EXIT_PASS, "fail": EXIT_FAIL}.get(self.verdict, EXIT_INCOMPLETE)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "tier": self.tier,
            "verdict": self.verdict,
            "rows": [
                {
                    "row": row.number,
                    "name": row.name,
                    "status": row.status.value,
                    "details": list(row.details),
                }
                for row in self.rows
            ],
            "verdicts": [asdict(verdict) for verdict in self.verdicts],
        }


# ---------------------------------------------------------------------------
# Transcripts: discovery and the corpus they make.
# ---------------------------------------------------------------------------


def discover_transcript_files(root: Path) -> list[tuple[Path, TranscriptFile]]:
    """Every ``transcripts.json`` under *root*, with its directory, in path order.

    Strict: a file that cannot be read raises. The harness itself discovers through
    :func:`discover_transcripts`, which reports such a file instead.
    """
    return [
        (path.parent, load_transcript_file(path))
        for path in sorted(root.rglob(TRANSCRIPT_FILE_NAME))
    ]


def _describe(error: BaseException) -> str:
    """One line saying what went wrong, without a pydantic dump or a traceback."""
    if isinstance(error, ValidationError):
        found = [
            f"{'.'.join(str(part) for part in item['loc']) or 'file'}: {item['msg']}"
            for item in error.errors()[:3]
        ]
        return "; ".join(found) or "validation failed"
    text = str(error).strip().splitlines()
    return f"{type(error).__name__}: {text[0]}" if text else type(error).__name__


@dataclass(frozen=True)
class UnreadableTranscriptFile:
    """A ``transcripts.json`` the harness could not read, and what it could tell of it."""

    problem: str
    #: The scanners the file's raw JSON names, or None when it could not be read that
    #: far (then every scanner is told, since it may be the one that file records).
    scanners: Optional[frozenset[str]] = None

    def concerns(self, scanner: str) -> bool:
        return self.scanners is None or scanner in self.scanners


@dataclass(frozen=True)
class Discovery:
    """What one walk of a transcript root found: the readable files, and the others."""

    files: tuple[tuple[Path, TranscriptFile], ...] = ()
    unreadable: tuple[UnreadableTranscriptFile, ...] = ()


def _scanners_named_by(data: Any) -> Optional[frozenset[str]]:
    """The scanners a damaged transcript file still names, or None for every scanner.

    This runs over a file :func:`parse_transcript_file` refused, so no key holds a
    promised shape: a ``transcripts`` that is not a list is part of the damage, never
    a reason to raise out of the walk. And a damaged file that names no scanner is
    everyone's problem (None), not no one's: an empty set would report it to no row.
    """
    if not isinstance(data, Mapping):
        return None
    names: set[str] = set()
    transcripts = data.get("transcripts")
    for entry in transcripts if isinstance(transcripts, (list, tuple)) else ():
        if not isinstance(entry, Mapping):
            continue
        if isinstance(entry.get("scanner"), str):
            names.add(entry["scanner"])
        also = entry.get("also_for")
        if isinstance(also, (list, tuple)):
            names.update(s for s in also if isinstance(s, str))
    unrecorded = data.get("unrecorded")
    for entry in unrecorded if isinstance(unrecorded, (list, tuple)) else ():
        if isinstance(entry, Mapping) and isinstance(entry.get("scanner"), str):
            names.add(entry["scanner"])
    return frozenset(names) or None


def discover_transcripts(root: Path) -> Discovery:
    """Every ``transcripts.json`` under *root*: the readable ones with their directory,
    and a description of each that is not valid JSON or not a valid transcript file
    (a newer schema, a bad shape), so one damaged file never stops the walk."""
    files: list[tuple[Path, TranscriptFile]] = []
    unreadable: list[UnreadableTranscriptFile] = []
    for path in sorted(root.rglob(TRANSCRIPT_FILE_NAME)):
        shown = path.relative_to(root).as_posix()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        # RecursionError: a file nested deeper than the interpreter's limit is one
        # damaged file, never the end of the walk (the contract above).
        except (OSError, ValueError, RecursionError) as error:
            unreadable.append(
                UnreadableTranscriptFile(
                    f"{shown} cannot be read as JSON ({_describe(error)})"
                )
            )
            continue
        try:
            files.append((path.parent, parse_transcript_file(data)))
        except (ValueError, RecursionError) as error:
            unreadable.append(
                UnreadableTranscriptFile(
                    f"{shown} is not a transcript file this ASH reads "
                    f"({_describe(error)})",
                    _scanners_named_by(data),
                )
            )
    return Discovery(tuple(files), tuple(unreadable))


def transcripts_of(
    scanner: str, files: Sequence[tuple[Path, TranscriptFile]]
) -> list[tuple[Path, ToolTranscript]]:
    return [
        (base, transcript)
        for base, file in files
        for transcript in file.transcripts
        if scanner in transcript.scanners
    ]


def unrecorded_reasons(
    scanner: str, files: Sequence[tuple[Path, TranscriptFile]]
) -> list[str]:
    return [
        row.reason
        for _base, file in files
        for row in file.unrecorded
        if row.scanner == scanner
    ]


def _load_sarif(path: Path) -> SarifReport:
    return SarifReport.model_validate(json.loads(path.read_text(encoding="utf-8")))


Prep = Callable[
    [ToolTranscript, Path, Path], Iterator[tuple[SarifReport, list[Result]]]
]

_BUILTIN_SCANNERS = "automated_security_helper.plugin_modules.ash_builtin.scanners"


def _prep_cfn_guard(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    cls = resolve_ref(f"{_BUILTIN_SCANNERS}.cfn_guard_scanner:CfnGuardScanner")
    report = _load_sarif(file)
    yield report, cls.normalize_results(report, "template.yaml")


def _prep_cfn_lint(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    module = f"{_BUILTIN_SCANNERS}.cfn_lint_scanner"
    cls = resolve_ref(f"{module}:CfnLintScanner")
    report = _load_sarif(file)
    # The resource comes from the JSON run beside the SARIF, when one is
    # committed. The scanner attaches it as each batch is read, before
    # normalize_report relocates the results, so the keys still match.
    companion = file.with_suffix(".json")
    if companion.is_file():
        resolve_ref(f"{module}:attach_cfn_lint_resources")(
            report,
            resolve_ref(f"{module}:cfn_lint_resources")(
                json.loads(companion.read_text(encoding="utf-8"))
            ),
        )
    # normalize_report reads no instance state: it locates results, maps
    # severities and sorts rules in place.
    cls.normalize_report(None, report)
    yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_cfn_nag(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    report = _load_sarif(file)
    resolve_ref(f"{_BUILTIN_SCANNERS}.cfn_nag_scanner:attach_cfn_nag_resources")(report)
    yield report, [r for run in report.runs or [] for r in run.results or []]


def _report_with_rules(tool_name: str, rules: Sequence[Any]) -> SarifReport:
    """A report whose one run declares *rules* on its driver and holds no results:
    the results are yielded beside it, and the rule-level facets (help link, tags)
    are read from the run."""
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


def _prep_guarddog(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    convert = resolve_ref(
        "automated_security_helper.plugin_modules.ash_guarddog_plugins."
        "guarddog_scanner:convert_guarddog_scan_result"
    )
    parts = file.stem.split("_")
    if len(parts) < 2 or not parts[1] or parts[0] not in ("scan", "verify"):
        raise ValueError(
            f"guarddog results file {file.name!r} is not named scan_<ecosystem>... or "
            "verify_<ecosystem>...; the prep reads the ecosystem from the file name"
        )
    ecosystem = parts[1]
    if file.name.startswith("verify_"):
        # Verify mode is where the adapter writes package identity: a committed
        # verify capture is a list of {dependency, version, result} entries over
        # the manifest committed beside it, converted the way the scanner's own
        # verify path converts them.
        manifest_line_for = resolve_ref(
            "automated_security_helper.plugin_modules.ash_guarddog_plugins."
            "guarddog_scanner:manifest_line_for"
        )
        manifest = file.with_suffix(".txt")
        manifest_text = manifest.read_text(encoding="utf-8")
        for entry in json.loads(file.read_text(encoding="utf-8")):
            converted = convert(
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
        return
    document = json.loads(file.read_text(encoding="utf-8"))
    converted = convert(
        document, uri_prefix="", ecosystem=ecosystem, include_capabilities=True
    )
    yield (
        _report_with_rules("guarddog", list(converted.rules.values())),
        list(converted.results),
    )


def _prep_actionlint(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    build_sarif = resolve_ref(f"{_BUILTIN_SCANNERS}.actionlint_scanner:build_sarif")
    payload = json.loads(file.read_text(encoding="utf-8"))
    document = build_sarif(payload, 1 if payload.get("errors") else 0)
    report = SarifReport.model_validate(document)
    yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_betterleaks(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    cls = resolve_ref(
        "automated_security_helper.plugin_modules.ash_betterleaks_plugins."
        "betterleaks_scanner:BetterleaksScanner"
    )
    report = cls.normalize_results(_load_sarif(file))
    yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_checkov(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    attach = resolve_ref(
        f"{_BUILTIN_SCANNERS}.checkov_scanner:attach_checkov_resources"
    )
    resources = resolve_ref(f"{_BUILTIN_SCANNERS}.checkov_scanner:checkov_resources")
    sarif = json.loads(file.read_text(encoding="utf-8"))
    side = json.loads(file.with_suffix(".json").read_text(encoding="utf-8"))
    attach(sarif, resources(side))
    report = SarifReport.model_validate(sarif)
    yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_detect_secrets(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    cls = resolve_ref(
        f"{_BUILTIN_SCANNERS}.detect_secrets_scanner:DetectSecretsScanner"
    )
    results = []
    for _key, secrets in json.loads(file.read_text(encoding="utf-8")):
        for secret in secrets:
            results.append(
                cls.build_secret_result(
                    finding_type=secret["type"],
                    uri=secret["filename"],
                    line_number=secret["line_number"],
                    start_column=secret.get("ash_start_column"),
                )
            )
    report = SarifReport.model_validate({"version": "2.1.0", "runs": []})
    yield report, results


def _prep_gitleaks(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    cls = resolve_ref(f"{_BUILTIN_SCANNERS}.gitleaks_scanner:GitleaksScanner")
    report = cls.normalize_results(_load_sarif(file))
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


def _prep_trivy(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    import tempfile

    cls = resolve_ref(f"{_BUILTIN_SCANNERS}.trivy_scanner:TrivyScanner")
    with tempfile.TemporaryDirectory(prefix="conformance-trivy-") as scratch:
        target = _materialized(base / "fixture_repo", Path(scratch))
        report = cls._attach_package_identity(_load_sarif(file), target)
        # A misconfiguration's resource comes from the JSON capture beside its
        # SARIF, when there is one.
        companion = file.with_suffix(".json")
        if companion.is_file():
            base_module = f"{_BUILTIN_SCANNERS}._trivy_scanner_base"
            resolve_ref(f"{base_module}:attach_trivy_resources")(
                report,
                resolve_ref(f"{base_module}:trivy_misconfig_resources")(
                    json.loads(companion.read_text(encoding="utf-8"))
                ),
            )
        yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_npm_audit(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    import tempfile

    from automated_security_helper.config.ash_config import AshConfig

    cls = resolve_ref(f"{_BUILTIN_SCANNERS}.npm_audit_scanner:NpmAuditScanner")
    # The conversion constructs a default-configured scanner, whose model
    # carries forward references to AshConfig; resolve them the way the other
    # construction tests do.
    AshConfig.model_rebuild()
    with tempfile.TemporaryDirectory(prefix="conformance-npmaudit-") as scratch:
        target = _materialized(base / "fixture_repo", Path(scratch))
        audit = json.loads(file.read_text(encoding="utf-8"))
        report = cls.convert_results(
            audit, target, lock_file=target / "package-lock.json"
        )
        yield report, [r for run in report.runs or [] for r in run.results or []]


#: The template each committed cdk-nag report CSV was generated over. The pairing
#: is data the recording carries (the corpus gate pins the same pairs), so a new
#: report file forces a row here.
_CDK_NAG_TEMPLATES: Mapping[str, str] = {
    "AwsSolutions-test-yaml-NagReport.csv": "test-yaml.template.json",
    "AwsSolutions-test-yaml-cfn-NagReport.csv": "cfn-and-python-test-yaml.template.json",
}


def _prep_cdk_nag(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    import csv

    from automated_security_helper.utils.cdk_nag_wrapper import (
        _NagFinding,
        build_nag_results,
    )
    from automated_security_helper.utils.cfn_template_model import (
        get_model_from_template_text,
    )

    pack = file.name.split("-")[0]
    with file.open(encoding="utf-8", newline="") as handle:
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
    template_path = file.parent / _CDK_NAG_TEMPLATES[file.name]
    template_text = template_path.read_text(encoding="utf-8")
    model = get_model_from_template_text(template_text, template_path)
    if model is None:
        raise ValueError(f"{template_path} did not parse as a template")
    per_pack = build_nag_results(
        {pack: findings},
        model,
        template_path,
        template_text.splitlines(),
    )
    nag_results = [r for results in per_pack.values() for r in results]
    # The run the scanner writes carries one descriptor per rule, which is where
    # the rule's help link lives; build it the way scan() does.
    descriptor_for = resolve_ref(
        f"{_BUILTIN_SCANNERS}.cdk_nag_scanner:_reporting_descriptor_for"
    )
    representatives: dict[Any, Result] = {}
    for result in nag_results:
        representatives.setdefault(result.ruleId, result)
    rules = [
        descriptor_for(rep, tool_name="cdk-nag", tool_type="IAC")
        for rep in representatives.values()
    ]
    yield _report_with_rules("ash-cdk-nag-wrapper", rules), nag_results


def _prep_ferret_scan(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    """The recorded ``ferret-scan --format sarif`` output through the adapter's own
    base-relative URI resolution, the step it applies before the report is built."""
    resolve_uri_base_ids = resolve_ref(
        "automated_security_helper.plugin_modules.ash_ferret_plugins."
        "ferret_scanner:_resolve_sarif_uri_base_ids"
    )
    document = json.loads(file.read_text(encoding="utf-8"))
    resolve_uri_base_ids(document)
    report = SarifReport.model_validate(document)
    yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_grype(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    """The recorded ``grype -o sarif`` output through the adapter's own
    post-processing (URIs, package identity, fix state). The scan target is an empty
    directory: the recording was taken over an SBOM, so no lockfile sits beside it
    for the package-path lookup."""
    import tempfile

    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    cls = resolve_ref(f"{_BUILTIN_SCANNERS}.grype_scanner:GrypeScanner")
    # The scanner's model carries forward references to AshConfig; resolve them the
    # way the npm-audit prep does.
    AshConfig.model_rebuild()
    with tempfile.TemporaryDirectory(prefix="conformance-grype-") as scratch:
        target = Path(scratch) / "src"
        target.mkdir()
        scanner = cls(
            context=PluginContext(
                source_dir=target, output_dir=Path(scratch) / "output"
            )
        )
        report = scanner._post_process_sarif(_load_sarif(file), [], target)
        yield report, [r for run in report.runs or [] for r in run.results or []]


def _prep_snyk_code(
    transcript: ToolTranscript, base: Path, file: Path
) -> Iterator[tuple[SarifReport, list[Result]]]:
    """The SARIF through the adapter's own rule-CWE normalization, the one step the
    scanner applies before it builds the report."""
    normalize = resolve_ref(
        "automated_security_helper.plugin_modules.ash_snyk_plugins."
        "snyk_code_scanner:normalize_rule_cwe_into_tags"
    )
    document = normalize(json.loads(file.read_text(encoding="utf-8")))
    report = SarifReport.model_validate(document)
    yield report, [r for run in report.runs or [] for r in run.results or []]


#: Registered adapter preps: native or adapter-normalized bytes through the adapter's
#: own pure function. A prep never runs a tool. A transcript names one in
#: ``adapter_prep``.
PREPS: Mapping[str, Prep] = {
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
    transcript: ToolTranscript, base: Path
) -> Iterator[tuple[Any, Result]]:
    """``(run or None, result)`` for every result of one transcript's SARIF-bearing files."""
    for entry in transcript.results:
        file = base / entry.path
        if transcript.adapter_prep is not None:
            for report, results in PREPS[transcript.adapter_prep](
                transcript, base, file
            ):
                run = report.runs[0] if report.runs else None
                for result in results:
                    yield run, result
        elif entry.format == "sarif":
            for run in _load_sarif(file).runs or []:
                for result in run.results or []:
                    yield run, result


def _readable_one(transcript: ToolTranscript) -> bool:
    """Whether one transcript's results can be read as findings: observable, and
    either SARIF as written or native bytes with an adapter prep."""
    return transcript.observable and (
        transcript.adapter_prep is not None
        or any(r.format == "sarif" for r in transcript.results)
    )


def _readable(
    transcripts: Sequence[tuple[Path, ToolTranscript]],
) -> list[tuple[Path, ToolTranscript]]:
    """The transcripts whose results can be read as findings (:func:`_readable_one`)."""
    return [(base, t) for base, t in transcripts if _readable_one(t)]


def _flats_of(
    scanner: str, kind: str, transcript: ToolTranscript, base: Path
) -> list[FlatVulnerability]:
    if transcript.adapter_prep is not None and transcript.adapter_prep not in PREPS:
        raise ValueError(
            f"it names adapter prep {transcript.adapter_prep!r}, which is not "
            f"registered (registered: {', '.join(sorted(PREPS))})"
        )
    return [
        FlatVulnerability.from_sarif_result(result, scanner, kind, run)
        for run, result in _results_with_runs(transcript, base)
    ]


def observed_frame(
    scanner: str,
    transcripts: Sequence[tuple[Path, ToolTranscript]],
    tool_type: Optional[str] = None,
    *,
    current_only: bool = False,
) -> Optional[dict[str, tuple[int, int]]]:
    """Per facet ``(non_null_count, total_results)`` over the scanner's transcripts, or
    None when none of them can be read as results (native bytes with no registered prep).

    Strict: a transcript whose results cannot be read raises. ``current_only`` leaves
    out the ``historical`` recordings. The harness reads through
    :func:`observe_transcripts` instead, which reports an unreadable transcript.
    """
    readable = _readable(
        [(b, t) for b, t in transcripts if not current_only or t.retention == "current"]
    )
    if not readable:
        return None
    kind = tool_type or SCANNER_TOOL_TYPES[scanner]
    return observed_counts(
        flat
        for base, transcript in readable
        for flat in _flats_of(scanner, kind, transcript, base)
    )


@dataclass(frozen=True)
class Observed:
    """What the readable recordings of one scanner carry, and what could not be read."""

    #: Facet counts over every readable transcript, or None when none could be read.
    every: Optional[dict[str, tuple[int, int]]] = None
    #: The same over the ``current`` transcripts only, or None when none could be read.
    current: Optional[dict[str, tuple[int, int]]] = None
    #: One sentence per transcript that could not be read as results.
    problems: tuple[str, ...] = ()


def observe_transcripts(
    scanner: str,
    transcripts: Sequence[tuple[Path, ToolTranscript]],
    tool_type: str,
) -> Observed:
    """Like :func:`observed_frame`, but a transcript whose results cannot be read (a
    missing or damaged file, an invalid SARIF, an unregistered prep, an adapter that
    raises) is named in ``problems`` and left out, so one bad recording never stops the
    others from being judged. Each transcript is read once for both frames.

    A transcript :func:`_readable` leaves out (marked not observable, or native bytes
    with no adapter prep) is silently absent from the frames, UNLESS it is ``current``
    and its exclusion leaves the scanner with no current frame at all: then every such
    transcript is named in ``problems``, because the MAPPED cells are judged over the
    current frame and a silent exclusion here would leave the row green with no facet
    observed (the caller's skip of those judgments presumes the cause is on the row).
    """
    read: list[tuple[ToolTranscript, list[FlatVulnerability]]] = []
    problems: list[str] = []
    unread_current: list[ToolTranscript] = []
    for base, transcript in transcripts:
        if not _readable_one(transcript):
            if transcript.retention == "current":
                unread_current.append(transcript)
            continue
        try:
            read.append((transcript, _flats_of(scanner, tool_type, transcript, base)))
        except Exception as error:  # noqa: BLE001 - a damaged recording is a finding
            problems.append(
                f"{transcript.id}: its results could not be read ({_describe(error)})"
            )
    has_current = any(t.retention == "current" for t, _f in read)
    if not has_current:
        for transcript in unread_current:
            why = (
                "it is marked not observable"
                if not transcript.observable
                else "native bytes with no adapter prep and no SARIF entry"
            )
            problems.append(
                f"{transcript.id}: a current recording whose results cannot be read "
                f"as findings ({why}), and no other current recording's can; record "
                "a readable current transcript, or mark this one historical with the "
                "reason"
            )
    return Observed(
        every=observed_counts(f for _t, flats in read for f in flats) if read else None,
        current=observed_counts(
            f for t, flats in read if t.retention == "current" for f in flats
        )
        if has_current
        else None,
        problems=tuple(problems),
    )


# ---------------------------------------------------------------------------
# The rows.
# ---------------------------------------------------------------------------


class PluginLoadError(RuntimeError):
    """A manifest's scanner entry point cannot be imported: the plugin is not
    installed or its manifest is wrong, which is not a verdict on the promotion bar."""


def _scanner_class(manifest: ScannerManifest) -> type:
    # Exception, not a named few: an import executes the plugin module, so a
    # SyntaxError or a RuntimeError raised at its top level is the same finding
    # (this plugin cannot be loaded), never a traceback out of the verify run.
    try:
        return resolve_ref(manifest.entry_points.scanner)
    except Exception as error:  # noqa: BLE001 - an unloadable plugin is a finding
        raise PluginLoadError(
            f"{manifest.name}'s scanner entry point {manifest.entry_points.scanner!r} "
            f"cannot be loaded ({_describe(error)})"
        ) from error


def _own_row(cls: type, attribute: str) -> Any:
    """The register row *cls* declares itself, or None: one lookup rule for every
    register (``vars``, never an inherited attribute)."""
    return vars(cls).get(attribute)


def _tool_type_of(name: str, cls: type, override: Optional[str]) -> Optional[str]:
    """The scanner's tool type: the caller's override, else the shipped table, else
    what its operational row declares, else the class default, else None.

    The shipped table outranks the operational row so this resolver and
    :func:`observed_frame` (which the parity gates drive, and which reads
    ``SCANNER_TOOL_TYPES`` directly) cannot read one scanner's flat rows under two
    different tool types: the verify bar and the PR gate judge one table.
    """
    if override:
        return override
    shipped = SCANNER_TOOL_TYPES.get(name)
    if shipped:
        return shipped
    operational = _own_row(cls, OPERATIONAL_FACETS_ATTR)
    declared = getattr(getattr(operational, "targets", None), "tool_type", None)
    value = getattr(declared, "value", declared)
    if isinstance(value, str) and value and value != "UNKNOWN":
        return value
    return scanner_tool_type(name)


def _category_problems(name: str, cls: type) -> list[str]:
    """The category refusals of *cls*'s own operational row.

    A row that names no scan category, and a row that names several while the
    plugin keeps the base ``classify_result`` (``ash plugin verify`` has no run, so
    it reads the can-serve set). A class with no row of its own is refused by bar
    row 2 (``_row_operational``), not here. A ``classify_result`` inherited from an
    intermediate base counts as an override.
    """
    row = _own_row(cls, OPERATIONAL_FACETS_ATTR)
    if not isinstance(row, ScannerOperationalFacets):
        return []
    categories = row.targets.categories
    if not categories:
        every = ", ".join(category.value for category in ScanCategory)
        return [
            (
                f"{name}: its operational row names no scan category; declare "
                f"targets.categories (one of: {every})"
            )
        ]
    if len(categories) == 1:
        return []
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase

    classifier = getattr(cls, "classify_result", None)
    if classifier is not None and classifier is not ScannerPluginBase.classify_result:
        return []
    listed = ", ".join(category.value for category in categories)
    return [
        (
            f"{name}: its operational row names {len(categories)} scan categories "
            f"({listed}) and the plugin does not override classify_result; declare "
            "one category or give the plugin a classify_result"
        )
    ]


def _digest_problems(transcript: ToolTranscript, base: Path) -> list[str]:
    try:
        return verify_digests(transcript, base)
    except OSError as error:
        return [
            f"{transcript.id}: the bytes it names cannot be read ({_describe(error)})"
        ]


def _row_facets(
    manifest: ScannerManifest,
    discovery: Discovery,
    pins: Mapping[str, str],
    tool_type: Optional[str],
) -> tuple[BarRow, tuple[Verdict, ...]]:
    name = manifest.name
    problems: list[str] = [
        file.problem for file in discovery.unreadable if file.concerns(name)
    ]
    mine = transcripts_of(name, discovery.files)
    if not mine:
        reasons = unrecorded_reasons(name, discovery.files)
        problems.append(
            f"{name} has no recorded transcript"
            + (f" ({reasons[0]})" if reasons else "")
            + "; record one (a transcripts.json beside its fixture)"
        )
    # A recording whose bytes failed their digest is not evidence of anything: it is
    # named, and left out of what the facets are judged over.
    sound: list[tuple[Path, ToolTranscript]] = []
    for base, transcript in mine:
        found = _digest_problems(transcript, base)
        problems.extend(found)
        if not found:
            sound.append((base, transcript))
    pinned = {name: pin.tool for pin in manifest.provisioning.tool_pins[:1]}
    problems.extend(stale_transcripts((t for _base, t in mine), pins, pinned))
    if pinned and mine and not any(t.retention == "current" for _b, t in mine):
        problems.append(
            f"{name} pins {pinned[name]} but every recorded transcript is historical; "
            "re-record at the pin (a promotion is judged over a recording of the "
            "tool as shipped)"
        )
    verdicts: list[Verdict] = []
    cls = _scanner_class(manifest)
    problems.extend(_category_problems(name, cls))
    declared = _own_row(cls, SCANNER_FACETS_ATTR)
    if declared is None:
        problems.append(f"{name}'s scanner class declares no facets register row")
    elif sound:
        kind = _tool_type_of(name, cls, tool_type) or ScannerToolType.UNKNOWN.value
        observed = observe_transcripts(name, sound, kind)
        problems.extend(observed.problems)
        every_hint = (
            f"{name}'s transcripts hold no readable results (no SARIF, no "
            "registered adapter prep)"
        )
        current_hint = (
            f"{name} has no current recording that can be read as results (a "
            "mapped cell is judged over a recording of the tool as shipped, "
            "never over a historical one)"
        )
        # When no current recording could be read at all AND the cause is
        # already a detail on this row (a pinned scanner whose every
        # recording is historical, a current recording that failed its
        # digest, a current recording observe_transcripts named because it
        # could not be read as findings), the per-facet MAPPED judgments
        # would restate that one cause once per facet; the cause row is the
        # finding. An unpinned scanner with only historical recordings
        # records no such cause, so its MAPPED cells are still judged (and
        # red) rather than silent. The premise holds because every way a
        # current transcript of `mine` can fail to reach the current frame
        # leaves a detail: its digest (above), or observe_transcripts'
        # problems (an unreadable or raising recording).
        had_current = any(t.retention == "current" for _b, t in mine)
        cause_recorded = had_current or bool(pinned)
        for facet in FACET_NAMES:
            state: FacetState = getattr(declared, facet).state
            mapped = state is FacetState.MAPPED
            if mapped and observed.current is None and cause_recorded:
                continue
            frame = observed.current if mapped else observed.every
            verdict = judge(
                name,
                facet,
                state,
                None if frame is None else frame.get(facet),
                corpus_hint=current_hint if mapped else every_hint,
            )
            verdicts.append(verdict)
            # An "owed" verdict (a declared-UNCONFIRMED cell) blocks promotion
            # like a FAIL: honest-ignorance states must be resolved to promote
            # (the register consistency gate lists a fixture owed without
            # failing; this bar names it on the row so it cannot read green
            # over a cell nobody has read).
            if verdict.outcome in ("FAIL", "owed"):
                problems.append(f"[{name}.{facet}] {verdict.detail}")
    status = RowStatus.RED if problems else RowStatus.GREEN
    return (
        BarRow(1, "facets green over committed transcripts", status, tuple(problems)),
        tuple(verdicts),
    )


def unconfirmed_cells(value: Any, path: str = "") -> Iterator[str]:
    """Every honest-ignorance cell under an operational register row, as ``path: what``."""
    if isinstance(value, BaseModel):
        for field_name in type(value).model_fields:
            child = getattr(value, field_name)
            here = f"{path}.{field_name}" if path else field_name
            if field_name == "unconfirmed" and child is not None:
                yield f"{path}: {child}"
            else:
                yield from unconfirmed_cells(child, here)
    elif isinstance(value, (tuple, list)):
        for index, child in enumerate(value):
            yield from unconfirmed_cells(child, f"{path}[{index}]")
    elif isinstance(value, Mapping):
        for key, child in value.items():
            yield from unconfirmed_cells(child, f"{path}[{key!r}]")
    elif isinstance(value, (set, frozenset)):
        for index, child in enumerate(sorted(value, key=repr)):
            yield from unconfirmed_cells(child, f"{path}{{{index}}}")
    elif isinstance(value, Enum):
        if value.value == "unconfirmed":
            yield f"{path}: unconfirmed"
    elif isinstance(value, str) and value.strip() == LICENSE_NOT_READ:
        yield f"{path}: {LICENSE_NOT_READ}"


_ROW_OPERATIONAL = "operational declarations complete, zero unconfirmed"


def _row_operational(manifest: ScannerManifest) -> BarRow:
    row = _own_row(_scanner_class(manifest), OPERATIONAL_FACETS_ATTR)
    if row is None:
        return BarRow(
            2,
            _ROW_OPERATIONAL,
            RowStatus.RED,
            (f"{manifest.name}'s scanner class declares no operational register row",),
        )
    cells = tuple(unconfirmed_cells(row))
    return BarRow(
        2,
        _ROW_OPERATIONAL,
        RowStatus.RED if cells else RowStatus.GREEN,
        tuple(f"unconfirmed cell {cell}" for cell in cells),
    )


def _row_live(
    manifest: ScannerManifest, live_results: Optional[Mapping[str, bool]]
) -> BarRow:
    operational = _own_row(_scanner_class(manifest), OPERATIONAL_FACETS_ATTR)
    required = (
        tuple(operational.platforms.provisionable)
        if operational is not None and operational.platforms.provisionable
        else ("host",)
    )
    if live_results is None:
        reason = (
            "no live-cell result was supplied; the live cell runs in CI "
            f"(it must be green on {', '.join(required)})"
        )
        return BarRow(
            3,
            "live-tool cell green on every declared platform",
            RowStatus.NOT_RUN,
            (reason,),
        )
    missing = [p for p in required if p not in live_results]
    red = [p for p in required if p in live_results and not live_results[p]]
    problems = [f"no live-cell result for {p}" for p in missing] + [
        f"the live cell is red on {p}" for p in red
    ]
    return BarRow(
        3,
        "live-tool cell green on every declared platform",
        RowStatus.RED if problems else RowStatus.GREEN,
        tuple(problems),
    )


def _row_provisioning(manifest: ScannerManifest) -> BarRow:
    name = "provisioning pinned, or user-installed with prerequisites"
    cls = _scanner_class(manifest)
    operational = _own_row(cls, OPERATIONAL_FACETS_ATTR)
    if operational is None:
        return BarRow(
            4,
            name,
            RowStatus.RED,
            ("no operational register row to read the runtime from",),
        )
    runtime = operational.runtime
    if runtime.kind is RuntimeKind.PINNED_BINARY:
        from automated_security_helper.utils.tool_downloads import get_tool_asset

        key = runtime.tool_versions_key or ""
        pinned = {pin.tool for pin in manifest.provisioning.tool_pins}
        problems: list[str] = []
        if key not in pinned:
            problems.append(
                f"the runtime names tool {key!r} but the manifest pins {sorted(pinned)}"
            )
        platforms = operational.platforms.provisionable
        if not platforms:
            problems.append("a pinned binary declares the platforms it provisions on")
        for platform in platforms:
            os_name, _, arch = platform.partition("/")
            try:
                asset = get_tool_asset(key, os_name, arch)
            except Exception as error:  # noqa: BLE001 - reported as the finding
                problems.append(f"{key} on {platform}: {error}")
                continue
            if not is_sha256(getattr(asset, "sha256", None)):
                problems.append(
                    f"{key} on {platform} carries no SHA-256 digest (64 lower-case "
                    "hex digits)"
                )
        return BarRow(
            4,
            name,
            RowStatus.RED if problems else RowStatus.GREEN,
            tuple(problems),
        )
    if runtime.kind is RuntimeKind.USER_INSTALLED_CLI:
        note = operational.prerequisites.note.strip()
        return BarRow(
            4,
            name,
            RowStatus.GREEN if note else RowStatus.RED,
            () if note else ("a user-installed CLI states its prerequisites",),
        )
    if runtime.kind is RuntimeKind.IN_PROCESS:
        return BarRow(4, name, RowStatus.GREEN, ())
    reason = (
        f"a {runtime.kind.value} tool is pinned by its package lock, which the "
        "manifest does not declare yet; this row cannot read it"
    )
    return BarRow(4, name, RowStatus.NOT_RUN, (reason,))


def _row_docs() -> BarRow:
    return BarRow(
        5,
        "docs generated from the manifest",
        RowStatus.NOT_RUN,
        ("no manifest-to-docs generator exists in this tree yet",),
    )


def verify_plugin(
    manifest: ScannerManifest,
    transcripts_root: Path,
    *,
    live_results: Optional[Mapping[str, bool]] = None,
    pins: Optional[Mapping[str, str]] = None,
    tool_type: Optional[str] = None,
    discovered: Optional[Discovery] = None,
) -> BarReport:
    """Evaluate the promotion bar for *manifest* over the transcripts under
    *transcripts_root*. Runs no tool and touches no network.

    *discovered* is a :func:`discover_transcripts` result for the root, so a run over
    many manifests walks and parses the tree once; without one it is discovered here.
    *tool_type* overrides the type the scanner's own declarations give.
    """
    found = (
        discovered if discovered is not None else discover_transcripts(transcripts_root)
    )
    facets_row, verdicts = _row_facets(
        manifest, found, pins if pins is not None else tool_versions(), tool_type
    )
    return BarReport(
        scanner=manifest.name,
        tier=manifest.tier.value
        if isinstance(manifest.tier, PluginTier)
        else str(manifest.tier),
        rows=(
            facets_row,
            _row_operational(manifest),
            _row_live(manifest, live_results),
            _row_provisioning(manifest),
            _row_docs(),
        ),
        verdicts=verdicts,
    )
