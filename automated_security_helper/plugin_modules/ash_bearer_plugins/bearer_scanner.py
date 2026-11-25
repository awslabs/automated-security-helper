# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Bearer: a SAST and sensitive-data-flow scanner, as a community scanner plugin.

What it runs
------------
``bearer scan`` with the ``sast`` scanner over the scan target's files. Bearer reads
source code in six languages and reports security findings (injection, hard-coded
credentials, weak cryptography and the like) with the rule's CWE ids.

Bearer is a community plugin: it is loaded only when ``ash_bearer_plugins`` is listed
in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a scan that
does not list the module is unchanged by its existence.

License gate
------------
Bearer is released under the Elastic License 2.0 (ELv2), which is not an OSI open
source license. ASH therefore never installs it and never redistributes it: there is
no pinned download, no entry in ``utils/tool_downloads.py`` and no Dockerfile step.
This plugin only runs a ``bearer`` the operator installed and put on PATH, as
``snyk-code`` runs a ``snyk`` the operator installed. Listing the module in
``ash_plugin_modules`` is the opt-in to running it; installing it is the operator's
act, under the operator's reading of the license. ``custom_install_commands`` stays
empty on purpose, so ``ash dependencies install`` has nothing to run for it.

Invocation
----------
Every run carries these flags, and none of them is configurable. They were read from
the Bearer 2.x command reference (``bearer scan`` flags) and not yet run against a
binary by this plugin's authors; the tests pin the argv, and the limits are listed in
the plugin README.

* ``--format=json`` and ``--output=<file>``: the report is written to a file under
  ASH's results directory. JSON is read, not SARIF: Bearer's SARIF writer gives every
  rule the level ``error`` whatever the rule's severity (it carries no severity at all),
  so a SARIF report cannot be rated. The JSON groups findings under their severity
  (``critical``, ``high``, ``medium``, ``low``, ``warning``), which is what this plugin
  converts to SARIF (``convert_bearer_report``).
* ``--scanner=sast``: Bearer's default, written out so a changed default or a
  ``BEARER_SCANNER`` environment variable cannot add the ``secrets`` scanner, which
  quotes the secrets it finds.
* ``--exit-code=2``: Bearer exits 1 both for policy breaches (its default) and for
  failures. Moving the findings code to 2 tells them apart, so 0 and 2 are success and
  anything else fails the scan.
* ``--quiet``, ``--no-color``, ``--hide-progress-bar``: nothing but the report matters.
* ``--force``: do not reuse Bearer's cache, so a result is never one an earlier run
  left.
* ``--disable-version-check``: Bearer makes no request to check for a new version.
* ``--config-file=<empty file>`` and ``--ignore-file=<empty file>``: Bearer reads
  ``bearer.yml`` and ``bearer.ignore`` from its working directory, the scanned tree,
  and either can drop rules or fingerprints before ASH sees them. ASH passes an empty
  file for each, kept outside the tree, so a repository cannot hide its own findings
  from the scan. ASH suppressions are the way to accept a finding.
* ``--skip-path=<dir>``: ASH's own output directory, when it is inside the target.

Every option is one ``--flag=value`` token, and the scan path follows ``--``.

Severity
--------
Bearer's own severity is kept, and the SARIF level is set to agree with it:

==========  ============  ===========
Bearer      ASH severity  SARIF level
==========  ============  ===========
critical    CRITICAL      error
high        HIGH          error
medium      MEDIUM        warning
low         LOW           note
warning     INFO          none
==========  ============  ===========

``warning`` is Bearer's lowest tier (below ``low``), reported for rules that flag
something worth a look and nothing more, so it is INFO. A finding under any other key,
or one that is not an object, is not dropped: it fails the scan, because a severity
this plugin cannot rate would otherwise vanish from the report.

Exit status and output
----------------------
0 and 2 are success (nothing found; findings found). Any other exit code fails the
scan even when a report is on disk. A report that is missing, empty, not JSON, or not
an object of severity lists fails the scan; it is never read as a clean one.

Offline
-------
The ``sast`` scanner applies rules compiled into the binary, and the version check is
off, so the scan is expected to need no network (``OfflineStrategy.BUNDLED``). That
rests on the command reference and has not been observed with the network blocked.

Sandbox
-------
The strict default (no network, baseline environment only). Nothing option- or
environment-derived is granted.
"""

from __future__ import annotations

import logging
from pathlib import Path
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
from automated_security_helper.config.tool_config_trust import empty_tool_directory
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit code Bearer is told to use when it finds policy breaches.
FINDINGS_EXIT_CODE = 2

#: Bearer's severities, most severe first, and what each becomes:
#: ``(ASH severity, SARIF level)``. See "Severity" in the module docstring.
BEARER_SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "error"),
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("LOW", "note"),
    "warning": ("INFO", "none"),
}

#: Where the operator reads how to install Bearer. ASH never installs it.
BEARER_INSTALL_URL = "https://github.com/Bearer/bearer"


def _relative_uri(filename: str) -> str:
    """A Bearer filename as a source-relative posix URI (no leading ``./``)."""
    uri = filename.replace("\\", "/")
    while uri.startswith("./"):
        uri = uri[2:]
    return uri


def _positive_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None
    return value


def convert_bearer_report(document: Any) -> Dict[str, Any]:
    """Convert Bearer's ``--format=json`` report into a SARIF 2.1.0 document.

    ``document`` maps a severity name to a list of findings. Each finding is read
    for ``id``, ``title``, ``description``, ``documentation_url``, ``cwe_ids``,
    ``filename``, ``fingerprint`` and the ``sink`` location (``start``, ``end``,
    ``column.start``, ``column.end``). The code snippet and extract are not copied.

    Raises:
        ScannerError: ``document`` is not an object of severity lists, holds a
            severity this plugin does not rate, or holds a finding that has no rule id
            or file name.
    """
    if not isinstance(document, dict):
        raise ScannerError(
            "its report is not a JSON object of findings grouped by severity, "
            "so it could not be graded"
        )
    unknown = sorted(str(key) for key in document if key not in BEARER_SEVERITY_MAP)
    if unknown:
        raise ScannerError(
            "its report holds findings under a severity this plugin does not rate "
            f"({', '.join(unknown)}), so they would be lost: "
            f"known severities are {', '.join(BEARER_SEVERITY_MAP)}"
        )
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for bearer_severity, (ash_severity, level) in BEARER_SEVERITY_MAP.items():
        findings = document.get(bearer_severity)
        if findings is None:
            continue
        if not isinstance(findings, list):
            raise ScannerError(
                f"its report's {bearer_severity!r} findings are not a list, so "
                "they could not be graded"
            )
        for finding in findings:
            if not isinstance(finding, dict):
                raise ScannerError(
                    f"its report holds a {bearer_severity!r} finding that is not "
                    "an object, so it could not be graded"
                )
            rule_id = finding.get("id")
            filename = finding.get("filename")
            if not isinstance(rule_id, str) or not rule_id:
                raise ScannerError("a finding in its report has no rule id")
            if not isinstance(filename, str) or not filename:
                raise ScannerError(f"a {rule_id} finding in its report has no filename")
            title = finding.get("title")
            title = title if isinstance(title, str) and title else rule_id
            cwe_ids = [
                f"CWE-{cwe}"
                for cwe in (finding.get("cwe_ids") or [])
                if isinstance(cwe, (str, int)) and str(cwe)
            ]
            if rule_id not in rules:
                rule: Dict[str, Any] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": title},
                    "properties": {"tags": ["bearer", "sast", "security", *cwe_ids]},
                }
                description = finding.get("description")
                if isinstance(description, str) and description:
                    rule["fullDescription"] = {"text": description}
                url = finding.get("documentation_url")
                if isinstance(url, str) and url.startswith(("https://", "http://")):
                    rule["helpUri"] = url
                rules[rule_id] = rule
            sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
            column = sink.get("column") if isinstance(sink.get("column"), dict) else {}
            region: Dict[str, Any] = {}
            for key, value in (
                ("startLine", _positive_int(sink.get("start"))),
                ("endLine", _positive_int(sink.get("end"))),
                ("startColumn", _positive_int(column.get("start"))),
                ("endColumn", _positive_int(column.get("end"))),
            ):
                if value is not None:
                    region[key] = value
            physical: Dict[str, Any] = {
                "artifactLocation": {"uri": _relative_uri(filename)}
            }
            if region:
                physical["region"] = region
            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": title},
                "locations": [{"physicalLocation": physical}],
                "properties": {
                    "issue_severity": ash_severity,
                    "tags": ["bearer", "sast", "security", *cwe_ids],
                },
            }
            fingerprint = finding.get("fingerprint")
            if isinstance(fingerprint, str) and fingerprint:
                result["partialFingerprints"] = {"bearer/v1": fingerprint}
            results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bearer",
                        "informationUri": "https://github.com/Bearer/bearer",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


class BearerScannerConfigOptions(ScannerOptionsBase):
    """Bearer takes no options of its own.

    ``severity_threshold``, ``scan_timeout`` and ``offline`` come from the base. There
    is deliberately no ``config_file``, rule-skip or ignore-file option: each would
    let a configuration the scanned tree can supply drop findings.
    """


class BearerScannerConfig(ScannerPluginConfigBase):
    name: Literal["bearer"] = "bearer"
    enabled: bool = True
    options: Annotated[
        BearerScannerConfigOptions,
        Field(description="Configure the bearer scanner"),
    ] = BearerScannerConfigOptions()


@ash_scanner_plugin
class BearerScanner(ScannerPluginBase[BearerScannerConfig]):
    """SAST and sensitive-data-flow analysis over the scan target using Bearer."""

    #: Not Python-only: Bearer is a native binary the operator installs.
    python_only: ClassVar[bool | None] = False

    # The sast rules are compiled into the binary and the version check is off.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name Bearer's ``--format=json`` report, which ``convert_bearer_report``
    #: turns into SARIF. No real-run fixture is committed, so the native fields are the
    #: command reference's reading of the report.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "id"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="the severity key the finding is listed under (critical, "
            "high, medium, low, warning), written to result level and properties "
            '"issue_severity" by convert_bearer_report',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "filename"',
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "sink.start" / "sink.end"',
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "sink.column.start" / "sink.column.end"',
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "title"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="pure SAST: findings are source locators, not deployable "
            "resources; the report carries a file and a sink region only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="pure SAST: findings are source locators, not deployable resources",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="bearer sast findings are source defects and carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="bearer sast findings are source defects and carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="bearer sast findings are source defects and carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="bearer rules are source-defect classes, not CVEs",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "cwe_ids", written as CWE-<n> tags on the rule '
            "and the result by convert_bearer_report",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='finding "fingerprint", written to partialFingerprints '
            '"bearer/v1"',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="bearer findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.DROPPED,
            native_field='finding "description"',
            reason="kept only as the rule's fullDescription, which the flat "
            "reader does not read as remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.DROPPED,
            native_field='finding "source" / "sink.content" code extract',
            reason="deliberately not copied: the extract quotes scanned code",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='finding "documentation_url", written to the rule helpUri',
            reason="the rule helpUri survives the SARIF model and dies at the flat "
            "reader, which reads no reference from it (observed empty over the "
            "reference corpus)",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="no native tags; the converter writes bearer, sast and "
            "security plus the CWE tags",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by '
            "convert_bearer_report",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="bearer",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "bearer_scanner.py offline_strategy, sandbox_requirements; module "
                    "header (Offline): sast rules are compiled into the binary and "
                    "--disable-version-check is passed"
                ),
                unconfirmed=(
                    "no run with the network blocked has been observed; one such "
                    "run settles it"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="the JSON report is converted to SARIF by convert_bearer_report",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="bearer scan over the target with --scanner=sast (_build_arguments)",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("bearer",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="the operator's installed Bearer (Elastic License 2.0, never "
                "installed by ASH); absent from TOOL_VERSIONS",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="Bearer's five severities map to ASH severities and SARIF levels "
                "(BEARER_SEVERITY_MAP)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="bearer.ignore in the scanned tree",
                        cite="bearer_scanner.py _build_arguments: --ignore-file points at an empty file outside the tree",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.TOOL_DEFAULT_FILTER,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="bearer.yml in the scanned tree (rule skips)",
                        cite="bearer_scanner.py _build_arguments: --config-file points at an empty file outside the tree",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="the report's fingerprint is mapped to partialFingerprints; no "
                "real-run fixture is committed to confirm it is stable across edits",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options only; no config file, rule-skip or ignore-file option",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 2),
                semantics="ASH passes --exit-code=2 because the tool's default 1 means both findings and failures",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_bearer_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no git repository or lockfile is required",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = {0, FINDINGS_EXIT_CODE}
    # Bearer's stderr can quote scanned code; keep it out of errors and failure text.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "bearer"
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = BearerScannerConfig()
        self.command = "bearer"
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _build_arguments; ToolArgs stays empty so nothing
        # from the base resolver can add a token Bearer would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # No setup_custom_install_commands on purpose: Bearer is ELv2, so ASH does not
    # install it. See "License gate" in the module docstring.

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("BearerScanner has no plugin context")
        return Path(self.context.source_dir)

    def _no_tree_config_dir(self) -> Path:
        """A new directory outside the scanned tree holding an empty config and ignore
        file, so Bearer never reads ``bearer.yml`` or ``bearer.ignore`` from the tree."""
        directory = empty_tool_directory("ash-no-bearer-config", context=self.context)
        directory = directory.resolve()
        for name in ("bearer.yml", "bearer.ignore"):
            with open_for_write(directory / name, encoding="utf-8") as handle:
                handle.write("")
        return directory

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source target (the working directory), else absolute."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _skip_paths(self, target: Path) -> List[str]:
        """ASH's output directories inside ``target``, as Bearer ``--skip-path`` values."""
        skipped: List[str] = []
        for relative in self._ash_output_dirs_inside(Path(target)):
            text = Path(relative).as_posix()
            if any(char in text for char in ",*"):
                raise ScannerError(
                    f"bearer was not started: ASH's output directory {text!r} has a "
                    "comma or an asterisk in its path, which Bearer's --skip-path "
                    "would read as a list or a pattern. Use --output-dir with a "
                    "plainer path."
                )
            if text not in skipped:
                skipped.append(text)
        return skipped

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full Bearer argv for one target: one ``--flag=value`` token per option
        and the scan path after ``--``."""
        config_dir = self._no_tree_config_dir()
        args: List[str] = [
            self.command or "bearer",
            *self.subcommands,
            "--format=json",
            f"--output={results_file.as_posix()}",
            "--scanner=sast",
            f"--exit-code={FINDINGS_EXIT_CODE}",
            "--quiet",
            "--no-color",
            "--hide-progress-bar",
            "--force",
            "--disable-version-check",
            f"--config-file={(config_dir / 'bearer.yml').as_posix()}",
            f"--ignore-file={(config_dir / 'bearer.ignore').as_posix()}",
        ]
        skipped = self._skip_paths(target)
        if skipped:
            args.append(f"--skip-path={','.join(skipped)}")
        args.extend(["--", self._scan_path(target)])
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Bearer run."""
        if self.results_dir is None:
            raise ScannerError("BearerScanner has no results directory")
        # One instance scans the source and then the converted target, and the base
        # keeps the worst exit code across runs.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "bearer.json")
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
        """Refuse a run Bearer did not finish, then read its JSON as SARIF.

        Raised before reading so a partial report cannot pass as a complete one. A
        missing file raises in the base; an empty one is the base's empty-results
        handling (a failure); JSON that does not parse fails the scan.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"bearer exited {self.exit_code}; it exits 0 when it finds nothing "
                f"and {FINDINGS_EXIT_CODE} when it finds issues, so this run failed"
            )
        raw = super()._read_results_file(results_file)
        if raw is None:
            return None
        return convert_bearer_report(raw)

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """The converted report already carries level and issue_severity."""
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "bearer")
        if not found:
            ASH_LOGGER.warning(
                "bearer executable not found in PATH. Bearer is licensed under the "
                "Elastic License 2.0, so ASH does not install it: install it "
                f"yourself ({BEARER_INSTALL_URL}) or exclude the scanner with "
                "--exclude-scanners bearer."
            )
        return found is not None


__all__ = [
    "BEARER_SEVERITY_MAP",
    "BearerScanner",
    "BearerScannerConfig",
    "BearerScannerConfigOptions",
    "FINDINGS_EXIT_CODE",
    "convert_bearer_report",
]
