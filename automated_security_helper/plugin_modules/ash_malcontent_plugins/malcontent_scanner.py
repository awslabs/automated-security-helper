# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Malcontent: supply-chain malware and capability discovery, as a community plugin.

What it runs
------------
``mal analyze`` (Chainguard's malcontent, Apache-2.0) over the scan target. It
interrogates every program, script and archive under the path with YARA-X rules and
lists the capabilities it finds, each with a risk level. Malcontent's own README says
``CRITICAL`` findings "should be considered malicious" and that ``analyze`` is
"paranoid", so expect false positives.

Malcontent is a community plugin: it is loaded only when ``ash_malcontent_plugins`` is
listed in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a scan
that does not list the module is unchanged by its existence.

Scan flow
---------
The template flow: ``_execute_scan`` builds the argv and ``_read_results_file`` turns
the JSON report Malcontent wrote into SARIF before the base class validates it. The
tool does not write SARIF, so the conversion is this module's.

Invocation
----------
Read from Malcontent's source at v1.28.2 (``cmd/mal/mal.go`` for the flags, defaults
and exit codes, ``pkg/malcontent`` for the report structs, ``pkg/render/json.go`` for
the document) and checked against the ``--format=json`` outputs that upstream keeps
under its ``tests/`` directory. No ``mal`` binary was run: it publishes none and
building it needs Go, Rust and YARA-X (see the plugin README).

* ``--format=json`` and ``--output=<file>``: the report is one JSON document,
  ``{"Files": {"<path>": <FileReport>}}``, written to a file under ASH's results
  directory. A stale one is removed before each run.
* ``--min-risk=low``: the documented default, written out so a changed default cannot
  change what ASH reports.
* ``--ignore-self``: do not report on the malcontent binary if it sits in the tree.
* Global flags go BEFORE the ``analyze`` subcommand, where Malcontent's usage text
  lists them. The scan path follows ``--``.
* ``--third-party=false``: Malcontent's third-party rules "may have licensing
  restrictions", and the flag is ON by default, so leaving it out would include them.
  ASH therefore passes it off explicitly, and a test pins the token. Only
  Malcontent's own rules run.
* Never passed: ``--image``/``--processes`` (reach registries or the host),
  ``--oci-auth`` (reads credentials), ``--exit-first-hit`` and ``--exit-first-miss``
  (turn findings into exit status 1).

Links
-----
Malcontent reads no link below the directory it is given: its walk
(``pkg/action/path.go``, ``scanWalk.walk``) skips every entry whose type is a symlink,
file or directory ("Ignore symlinked directories like regular directories"), and its
walker does not follow links below the start (``pkg/file/walk.go``). ASH hands it a
directory (``.`` for the source), so a link leaving the target is never read and the
command names none in an exclusion option. This was read from source, not measured
on a binary.

Severity
--------
Malcontent describes capabilities, not defects: most of what it lists is behavior a
legitimate program has too. Like capa, the low end is INFO. Each behavior is one SARIF
result, and ``issue_severity`` and the SARIF level agree:

* ``critical`` -> CRITICAL / error (Malcontent: "should be considered malicious")
* ``high``     -> HIGH / error
* ``medium``   -> MEDIUM / warning
* ``low`` and ``harmless`` -> INFO / none (a capability, not a finding)
* any other value -> HIGH / error: an unrecognized level errs to the more severe, so
  it is not hidden under the default threshold.

Exit status and output
----------------------
Malcontent exits 0 when it ran, whether or not it found anything (ASH never passes
``--exit-first-hit``). Its source maps a usage error or missing path to 22, an
unreadable path to 5, and any other failure to 2. Only 0 is a success; any other code
fails the scan even if a report is on disk. A report that is not JSON, or not an
object, fails the scan.

What the report may quote
-------------------------
Behaviors carry ``MatchStrings``, the text that matched in the scanned file. That text
can be anything the tree holds, a secret included, so it is never copied into SARIF,
the findings or the error list. Malcontent's stderr is likewise not copied into
``self.errors``.

Offline
-------
The rules are embedded in the binary ("Embedded rules to support air-gapped
networks"), so ``offline_strategy`` is BUNDLED.

Sandbox
-------
The strict default (no network, baseline environment only): nothing here needs more.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Executable names, in the order they are tried. The README builds ``out/mal`` and
#: the GoReleaser config names the binary ``malcontent``.
EXECUTABLE_NAMES = ("mal", "malcontent")

#: Risk level Malcontent reports -> (ASH severity, SARIF level). See "Severity".
MALCONTENT_RISK_MAP: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "error"),
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("INFO", "none"),
    "harmless": ("INFO", "none"),
}

#: An unrecognized risk level: the more severe choice.
UNKNOWN_RISK = ("HIGH", "error")


def severity_for(risk_level: Any) -> Tuple[str, str]:
    """``(issue_severity, SARIF level)`` for a Malcontent ``RiskLevel`` string."""
    return MALCONTENT_RISK_MAP.get(str(risk_level or "").strip().lower(), UNKNOWN_RISK)


def _relative_uri(path: str, target: Path) -> str:
    """A report path as a posix path relative to the scanned target."""
    text = str(path).replace("\\", "/")
    candidate = PurePosixPath(text)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(
                PurePosixPath(Path(target).absolute().as_posix())
            ).as_posix()
        except ValueError:
            return text.lstrip("/")
    while text.startswith("./"):
        text = text[2:]
    return text or "."


def convert_malcontent_report(document: Any, target: Path) -> Dict[str, Any]:
    """Convert Malcontent's ``--format=json`` document into a SARIF dict.

    Raises:
        ScannerError: ``document`` is not the ``{"Files": {...}}`` object.
    """
    if not isinstance(document, dict):
        raise ScannerError("its report is not a JSON object, so it is not graded")
    files = document.get("Files") or {}
    if not isinstance(files, dict):
        raise ScannerError("its report's Files member is not an object")

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for raw_path in sorted(files):
        report = files[raw_path]
        if not isinstance(report, dict) or report.get("Skipped"):
            continue
        uri = _relative_uri(report.get("Path") or raw_path, target)
        for behavior in report.get("Behaviors") or []:
            if not isinstance(behavior, dict):
                continue
            severity, level = severity_for(behavior.get("RiskLevel"))
            rule_id = str(
                behavior.get("ID") or behavior.get("RuleName") or "malcontent-behavior"
            )
            description = str(behavior.get("Description") or rule_id)
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "shortDescription": {"text": description},
                    **(
                        {"helpUri": behavior["RuleURL"]}
                        if isinstance(behavior.get("RuleURL"), str)
                        and behavior["RuleURL"].startswith(("http://", "https://"))
                        else {}
                    ),
                },
            )
            fingerprint = hashlib.sha256(
                f"{rule_id}\0{uri}".encode("utf-8", errors="replace")
            ).hexdigest()
            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"{description} (Malcontent risk: {behavior.get('RiskLevel') or 'unknown'})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {"malcontent/v1": fingerprint},
                "properties": {
                    "issue_severity": severity,
                    "tags": ["malware", "capability", "supply-chain"],
                    "malcontent_risk_level": behavior.get("RiskLevel"),
                },
            }
            results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "malcontent",
                        "informationUri": "https://github.com/chainguard-dev/malcontent",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


class MalcontentScannerConfigOptions(ScannerOptionsBase):
    """No Malcontent-specific options.

    ``severity_threshold``, ``scan_timeout`` and ``offline`` come from the base. Nothing
    here can point Malcontent at a file, a registry or a rule set the scanned tree
    chooses, so there is nothing for the operator-only lists to name.
    """


class MalcontentScannerConfig(ScannerPluginConfigBase):
    name: Literal["malcontent"] = "malcontent"
    enabled: bool = True
    options: Annotated[
        MalcontentScannerConfigOptions,
        Field(description="Configure the malcontent scanner"),
    ] = MalcontentScannerConfigOptions()


@ash_scanner_plugin
class MalcontentScanner(ScannerPluginBase[MalcontentScannerConfig]):
    """File capability and malware discovery over the scan target using Malcontent."""

    #: Not Python-only: Malcontent is a native binary.
    python_only: ClassVar[bool | None] = False

    # The YARA rules are embedded in the binary and ``analyze`` of a path makes no
    # network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: The facets register row (base/scanner_facets.py). Native fields name
    #: Malcontent's ``--format=json`` report, as ``convert_malcontent_report`` reads it.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='Files.<path>.Behaviors[] "ID" (else "RuleName")',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='Files.<path>.Behaviors[] "RiskLevel" through '
            "MALCONTENT_RISK_MAP, written as result level and property issue_severity",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="Files.<path>.Path (else the Files map key), made relative to the target",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="the report is per file and per behavior; the adapter writes startLine 1",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no column; behaviors are file-level",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='Files.<path>.Behaviors[] "Description" plus the "RiskLevel"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a scanned file, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a scanned file, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="behaviors are reported per file; the report names no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="behaviors are reported per file; the report names no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="behaviors are reported per file; the report names no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="capability findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='computed by the adapter: sha256 of Behaviors[] "ID" and the '
            "relative path, as partialFingerprints malcontent/v1",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="capability findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the report carries no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.DROPPED,
            native_field='Files.<path>.Behaviors[] "MatchStrings"',
            reason="the matched text is the scanned tree's own and can hold a secret, "
            "so it is deliberately never copied into SARIF",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field='Files.<path>.Behaviors[] "RuleURL" (http and https only), '
            "written as the SARIF rule helpUri",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native tags) the adapter writes malware, capability, "
            "supply-chain",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='Files.<path>.Behaviors[] "RiskLevel" kept as result property '
            "malcontent_risk_level",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py), checked by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="malcontent",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "malcontent_scanner.py offline_strategy, sandbox_requirements; "
                    "module header: the YARA rules are embedded, and --image, "
                    "--processes and --oci-auth are never passed"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="--format=json is converted to SARIF by convert_malcontent_report",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="`mal analyze` over the target; Malcontent walks it and decides what is a program, script or archive",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("mal",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="Malcontent publishes no release binaries, so ASH pins and "
                "provisions nothing; the operator builds it or uses its container image",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="RiskLevel maps through MALCONTENT_RISK_MAP; low and harmless are INFO",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="the adapter reads no repository-written ignore file or "
                "inline comment surface of Malcontent; findings are tuned with ASH "
                "suppressions",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="sha256 of rule id and relative path; no line, since behaviors are file-level",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no Malcontent-specific options; only Malcontent's embedded rules run (--third-party=false)",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 when it ran, whether or not it found anything (ASH never passes --exit-first-hit); any other code fails the scan",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_malcontent_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no git repository, lockfile or credential is required",
            ),
        )
    )

    # Malcontent exits 0 when it ran; see "Exit status and output".
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = MalcontentScannerConfig()
        self.command = EXECUTABLE_NAMES[0]
        self.subcommands = ["analyze"]
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing from
        # the base resolver can add a token Malcontent would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # Malcontent publishes no release binaries (see the plugin README), so there is no
    # pinned download to install: custom_install_commands is left empty and the binary
    # must already be on PATH, as in the container image the operator builds.

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: Malcontent walks the target itself and decides what is a program."""
        return None

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("MalcontentScanner has no plugin context")
        return Path(self.context.source_dir)

    def _executable(self) -> str:
        """The first of ``EXECUTABLE_NAMES`` found on PATH, else the primary name."""
        for name in EXECUTABLE_NAMES:
            if find_executable(name):
                return name
        return EXECUTABLE_NAMES[0]

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the subprocess runs there), absolute otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full argv for one target: global flags, ``analyze``, ``--``, the path."""
        return [
            self._executable(),
            "--format=json",
            f"--output={results_file.as_posix()}",
            "--min-risk=low",
            "--third-party=false",
            "--ignore-self",
            *self.subcommands,
            "--",
            self._scan_path(target),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Malcontent run."""
        if self.results_dir is None:
            raise ScannerError("MalcontentScanner has no results directory")
        # The base keeps the worst exit code across the source and converted runs.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "malcontent.json")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse a failed run, then convert Malcontent's JSON report to SARIF."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"malcontent exited {self.exit_code}; it exits 0 when it ran, so "
                "this run failed"
            )
        document = super()._read_results_file(results_file)
        if document is None:
            return None
        target = self._source_dir()
        return convert_malcontent_report(document, target)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code and keep stderr, which can quote the tree, out of errors."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where the log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (malcontent was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). malcontent's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop results under ASH's own output directory inside the target."""
        outputs = self._output_dirs_inside_target(target)
        if outputs:
            target_abs = Path(target).absolute()
            roots = [Path(os.path.normpath(target_abs / o)) for o in outputs]
            for run in sarif_report.runs or []:
                kept = []
                for result in run.results or []:
                    uri = None
                    for location in result.locations or []:
                        physical = location.physicalLocation
                        artifact = physical.root.artifactLocation if physical else None
                        uri = artifact.uri if artifact else uri
                    path = Path(os.path.normpath(target_abs / (uri or "")))
                    if uri and any(path.is_relative_to(root) for root in roots):
                        continue
                    kept.append(result)
                run.results = kept
        return sarif_report

    def _output_dirs_inside_target(self, target: Path) -> List[Path]:
        """ASH's output directories inside ``target``, relative to it."""
        found: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            found.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in found:
                found.append(relative)
        return found

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = any(find_executable(name) for name in EXECUTABLE_NAMES)
        if not found:
            ASH_LOGGER.warning(
                "malcontent executable (mal) not found in PATH. Malcontent publishes "
                "no release binaries; build it from source or use its container image "
                "(see the ash_malcontent_plugins README)."
            )
        return found


__all__ = [
    "EXECUTABLE_NAMES",
    "MALCONTENT_RISK_MAP",
    "MalcontentScanner",
    "MalcontentScannerConfig",
    "MalcontentScannerConfigOptions",
    "convert_malcontent_report",
    "severity_for",
]
