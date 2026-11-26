# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Polaris: Kubernetes manifest best-practice checks, as a community scanner plugin.

What it runs
------------
``polaris audit`` over the scanned tree's Kubernetes YAML (``*.yaml`` and ``*.yml``),
with the checks that ship inside the Polaris binary. Nothing here talks to a cluster:
``--audit-path`` makes Polaris read files instead.

Invocation (measured on Polaris v10.2.6, and read from ``cmd/polaris/audit.go`` and
``cmd/polaris/root.go`` in the Polaris repository)
-------------------------------------------------------------------------------
``polaris audit --audit-path=<path> --format=json --only-show-failed-tests
--set-exit-code-on-danger --disallow-exemptions --output-file=<results>/polaris.json``

* ``--audit-path`` makes Polaris audit YAML files instead of a cluster. A directory is
  walked; ``-`` would read standard input, so the path is always ``.`` or absolute.
* ``--format=json`` is the default; it is passed so a default change cannot alter the
  output ASH parses.
* ``--output-file`` writes the report to a file. Polaris then prints no report on
  standard output, which is why this is the template scan flow: ASH reads the file.
* ``--set-exit-code-on-danger`` makes Polaris exit 3 when any danger-level check failed.
  That separates "audit ran and found danger" (3) from "Polaris failed" (1: a path it
  cannot read, a config it cannot parse). Exit 0 is a run with no danger-level failure.
  The report is written before the exit code is chosen (measured: exit 3 with the file
  complete), and on exit 1 no file is written.
* ``--disallow-exemptions`` makes Polaris ignore the ``polaris.fairwinds.com/<check>-exempt``
  annotations on the audited manifests and the exemptions of a config file. The scanned
  tree controls those annotations, so honoring them would let the tree hide findings
  before ASH sees them; suppressions belong to ASH, where they are reported and counted.
* No ``--config`` is passed, so Polaris uses its built-in checks. The scanned tree cannot
  supply one (Polaris reads a config only when ``--config`` names it). This plugin has
  no option that names one.
* Every option is one ``--flag=value`` token, and ``--audit-path`` takes its value with
  ``=`` so the path is never read as a flag.

Output
------
Polaris's JSON has no file name and no line: each entry of ``Results`` is one Kubernetes
object (``Name``, ``Namespace``, ``Kind``), whose checks sit in ``Results`` (the
controller), in ``PodResult.Results`` (the pod template) and in
``PodResult.ContainerResults[].Results`` (one set per container). Each check is
``{ID, Message, Details, Success, Severity, Category}``. This module converts that
document to SARIF, and finds the file by reading the YAML under the scanned directory
for the object's ``kind``, ``metadata.name`` and ``metadata.namespace``. The reported
line is the line of ``metadata.name`` in that document. An object found in two files is
reported against both. An object that no regular file in the tree defines (for example
one Polaris read through a symbolic link to a file outside the tree) is dropped and
counted in a warning.

Severity
--------
``danger`` is HIGH with SARIF level ``error``; ``warning`` is MEDIUM with level
``warning``. Polaris checks are configuration best practice, not exploitable
vulnerabilities, so ``danger`` is not CRITICAL (the choice hadolint makes for its
``error``). A check with a severity Polaris does not document is rated HIGH, the more
severe choice. A check with ``Success`` true, or severity ``ignore``, is not a finding.

Exit status
-----------
0 and 3 are runs that completed. Any other code, 1 included, fails the scan even when a
report is on disk.

Offline
-------
The checks are compiled into the binary and an ``--audit-path`` run makes no network
call, so the strategy is BUNDLED.

Sandbox
-------
The strict default: no network and the baseline environment. No option or environment
variable of this plugin widens it.
"""

import logging
import os
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

import yaml
from pydantic import PrivateAttr, model_validator

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
from automated_security_helper.plugin_modules.ash_polaris_plugins.polaris_install import (
    polaris_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import read_bytes_at_most
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit code Polaris is told to use when a danger-level check failed.
DANGER_EXIT_CODE = 3

#: The report format version this converter was written against.
SUPPORTED_OUTPUT_MAJOR = "1."

#: Polaris severity -> (ASH issue_severity, SARIF level). See "Severity" above.
POLARIS_SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "danger": ("HIGH", "error"),
    "warning": ("MEDIUM", "warning"),
}

#: What an undocumented severity is rated: the more severe choice.
UNKNOWN_SEVERITY: Tuple[str, str] = ("HIGH", "error")

#: A YAML file larger than this is not indexed for locations.
MAX_INDEXED_FILE_BYTES = 8 * 1024 * 1024

_YAML_SUFFIXES = (".yaml", ".yml")

#: (kind, name) -> [(namespace, uri, line)] for every object defined in the tree.
ObjectIndex = Dict[Tuple[str, str], List[Tuple[str, str, int]]]


def _index_documents(path: Path, text: str) -> List[Tuple[str, str, str, int]]:
    """(kind, name, namespace, line) of every Kubernetes object in one YAML file.

    Composes the YAML into nodes without constructing Python objects, so a tag in the
    scanned file cannot run anything. A file that does not parse gives no entries; the
    same file is one Polaris skipped.
    """
    found: List[Tuple[str, str, str, int]] = []
    try:
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        return found

    def value_of(node: Any, key: str) -> Optional[Any]:
        if not isinstance(node, yaml.MappingNode):
            return None
        for k, v in node.value:
            if isinstance(k, yaml.ScalarNode) and k.value == key:
                return v
        return None

    for document in documents:
        kind = value_of(document, "kind")
        metadata = value_of(document, "metadata")
        name = value_of(metadata, "name")
        if not (
            isinstance(kind, yaml.ScalarNode) and isinstance(name, yaml.ScalarNode)
        ):
            continue
        namespace = value_of(metadata, "namespace")
        found.append(
            (
                kind.value,
                name.value,
                namespace.value if isinstance(namespace, yaml.ScalarNode) else "",
                name.start_mark.line + 1,
            )
        )
    return found


class PolarisScannerConfigOptions(ScannerOptionsBase):
    """Polaris has no options of its own.

    ``severity_threshold``, ``scan_timeout`` and ``offline`` come from the base. There is
    deliberately no option for a Polaris config file or for exemptions: both would let
    the scanned configuration decide which findings exist.
    """


class PolarisScannerConfig(ScannerPluginConfigBase):
    name: Literal["polaris"] = "polaris"
    enabled: bool = True
    options: PolarisScannerConfigOptions = PolarisScannerConfigOptions()


@ash_scanner_plugin
class PolarisScanner(ScannerPluginBase[PolarisScannerConfig]):
    """Kubernetes manifest checks over the scan target's YAML files using Polaris."""

    #: Not Python-only: Polaris is a native binary installed from its pinned release.
    python_only: ClassVar[bool | None] = False

    # The checks are compiled in and ``audit --audit-path`` makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name Polaris's own JSON; the corpus is the captured run in
    #: tests/test_data/scanners/polaris/captured/ and the SARIF the converter writes
    #: from it.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "ID" (the key of the Results map)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "Severity" (danger, warning, ignore) through '
            "POLARIS_SEVERITY_MAP onto issue_severity and the SARIF level",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(none in Polaris's JSON) the YAML file found by the "
            "object's Kind, Name and Namespace under the scanned tree",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(none in Polaris's JSON) the line of metadata.name in "
            "the located document; a start line only",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="Polaris reports an object and a check, never a column; the "
            "converter writes a start line only",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "Message", with "Details" when present, prefixed '
            "with Kind/Name and the container name",
        ),
        resource_id=FacetDecl(
            state=FacetState.DROPPED,
            native_field="entry Kind, Name and Namespace (Deployment web in demo)",
            reason="the object is a Kubernetes resource, but the adapter folds it "
            "into the message text and never writes ash_resource_id; binding "
            "resource-scoped suppressions is its own decision",
        ),
        resource_type=FacetDecl(
            state=FacetState.DROPPED,
            native_field='entry "Kind"',
            reason="carried in the message prefix only; the adapter writes no "
            "ash_resource_type",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="manifest checks carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="manifest checks carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="manifest checks carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="best-practice checks carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the check records carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="Polaris emits no fingerprint or hash for a check result",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="Polaris's Mutations list a patch for some checks, but the "
            "adapter reads no fix state from it",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the check record's Message states the problem; the only "
            "fix-shaped field is Mutations (a JSON patch), which is not read",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the JSON carries no source text of the object",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the check records carry no reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "Category" (Security, Reliability, Efficiency), '
            "lowercased, after the constant kubernetes tag",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the converter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="polaris",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "polaris_scanner.py offline_strategy, sandbox_requirements; "
                    "module header: the checks are compiled in and --audit-path "
                    "makes no network call"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="Polaris's own AuditData JSON, converted to SARIF by "
                "convert_polaris_output",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.IAC_KUBERNETES,),
                tool_type=ScannerToolType.IAC,
                selection="`polaris audit --audit-path` over the target; objects "
                "are located by reading the tree's *.yaml and *.yml files",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for Polaris.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(polaris_install.py: linux, darwin amd64/arm64 and windows/amd64), "
                "not by the shared tool_downloads table, so the register lists none",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="danger is HIGH and warning is MEDIUM; an undocumented value "
                "is HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="polaris.fairwinds.com/<check>-exempt annotations "
                        "on the audited manifests",
                        cite="polaris_scanner.py module header: ASH passes "
                        "--disallow-exemptions",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="no fingerprint; identity is file and the line of metadata.name",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options beyond the base; a Polaris config file "
                "is not passed, so the scanned tree cannot add checks",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 3),
                semantics="ASH passes --set-exit-code-on-danger: 3 is a completed "
                "run with a danger-level failure, 1 is a Polaris failure",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_polaris_plugins in ash_plugin_modules",),
                upstream_license="Apache-2.0 (source: the LICENSE file inside the "
                "v10.2.6 release archive, read 2026-11-25; no license or service "
                "gate, the binary is downloaded and never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="Kubernetes manifests in the scan set",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = {0, DANGER_EXIT_CODE}
    # The strict default (no network, baseline environment); see the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    _audit_target: Optional[Path] = PrivateAttr(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = PolarisScannerConfig()
        self.command = "polaris"
        self.subcommands = ["audit"]
        self.tool_type = ScannerToolType.IAC
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing from
        # the base resolver can add a token Polaris would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "PolarisScanner":
        """Install from the pinned release asset in ``polaris_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no Polaris entry, and
        building the commands from it raised at construction. This table never raises.
        """
        self.custom_install_commands.update(polaris_install_commands())
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("PolarisScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before Polaris runs whether a YAML file is Kubernetes."""
        return None

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the working directory), absolute otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full Polaris argv for one target, one ``--flag=value`` token each."""
        return [
            self.command or "polaris",
            *self.subcommands,
            f"--audit-path={self._scan_path(target)}",
            "--format=json",
            "--only-show-failed-tests=true",
            "--set-exit-code-on-danger=true",
            "--disallow-exemptions=true",
            f"--output-file={results_file.as_posix()}",
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Polaris run.

        ``global_ignore_paths`` is not translated: it is applied to every scanner's
        SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("PolarisScanner has no results directory")
        # One instance scans source then converted; do not carry the last exit code.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "polaris.json")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        self._audit_target = Path(target)  # read back when the report is converted
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse an unfinished run, then turn Polaris's JSON into a SARIF document."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"polaris exited {self.exit_code}; it exits 0 when no danger-level "
                f"check failed and {DANGER_EXIT_CODE} when one did, so this run failed"
            )
        raw = super()._read_results_file(results_file)
        if raw is None:
            return None
        target = self._audit_target or self._source_dir()
        return self.convert_polaris_output(raw, self._index_target(Path(target)))

    # ------------------------------------------------------------------
    # Locating objects
    # ------------------------------------------------------------------

    def _index_target(self, target: Path) -> ObjectIndex:
        """(kind, name) -> [(namespace, uri, line)...] for the YAML under ``target``.

        Regular files only (a link is not followed, so a file outside the tree is never
        read for locations), none under ASH's own output directories, each at most
        ``MAX_INDEXED_FILE_BYTES``. The uri is relative to ``target``.
        """
        index: ObjectIndex = {}
        output_dirs = list(self._ash_output_dirs_inside(target))
        own = self._output_dir_inside(target)
        if own is not None:
            output_dirs.append(own)
        skip = {(target / rel).absolute() for rel in output_dirs}
        base = target.absolute()
        roots = [base] if base.is_dir() else []
        files: List[Path] = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                here = Path(dirpath)
                dirnames[:] = sorted(
                    d for d in dirnames if (here / d).absolute() not in skip
                )
                for name in sorted(filenames):
                    if name.endswith(_YAML_SUFFIXES):
                        files.append(here / name)
        if base.is_file() and base.name.endswith(_YAML_SUFFIXES):
            files.append(base)
        for file in files:
            if file.is_symlink() or not file.is_file():
                continue
            try:
                data = read_bytes_at_most(file, MAX_INDEXED_FILE_BYTES + 1)
            except OSError:
                continue
            if len(data) > MAX_INDEXED_FILE_BYTES:
                continue
            uri = file.name if base.is_file() else file.relative_to(base).as_posix()
            for kind, name, namespace, line in _index_documents(
                file, data.decode("utf-8", errors="replace")
            ):
                index.setdefault((kind, name), []).append((namespace, uri, line))
        return index

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _failed_checks(
        entry: Dict[str, Any],
    ) -> List[Tuple[Optional[str], Dict[str, Any]]]:
        """(container name or None, check) for every failed check of one object."""
        out: List[Tuple[Optional[str], Dict[str, Any]]] = []

        def take(container: Optional[str], checks: Any) -> None:
            if not isinstance(checks, dict):
                return
            for key in sorted(checks):
                check = checks[key]
                if isinstance(check, dict) and check.get("Success") is False:
                    out.append((container, {"ID": key, **check}))

        take(None, entry.get("Results"))
        pod = entry.get("PodResult")
        if isinstance(pod, dict):
            take(None, pod.get("Results"))
            for container in pod.get("ContainerResults") or []:
                if isinstance(container, dict):
                    take(str(container.get("Name") or ""), container.get("Results"))
        return out

    @classmethod
    def convert_polaris_output(
        cls,
        document: Any,
        index: ObjectIndex,
    ) -> Dict[str, Any]:
        """Polaris audit JSON -> a SARIF 2.1.0 document.

        Raises ``ScannerError`` for anything that is not a Polaris audit document.
        """
        if not isinstance(document, dict) or "Results" not in document:
            raise ScannerError("its results are not a Polaris audit document")
        version = str(document.get("PolarisOutputVersion", ""))
        if not version.startswith(SUPPORTED_OUTPUT_MAJOR):
            raise ScannerError(
                f"its output version {version!r} is not one this plugin reads "
                f"({SUPPORTED_OUTPUT_MAJOR}x)"
            )
        entries = document.get("Results")
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise ScannerError("its results are not a Polaris audit document")

        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []
        unlocated = 0
        for entry in entries:
            if not isinstance(entry, dict):
                raise ScannerError("its results are not a Polaris audit document")
            kind = str(entry.get("Kind") or "")
            name = str(entry.get("Name") or "")
            namespace = str(entry.get("Namespace") or "")
            places = [
                (uri, line)
                for ns, uri, line in index.get((kind, name), [])
                if namespace == "" or ns in (namespace, "")
            ]
            checks = cls._failed_checks(entry)
            if checks and not places:
                unlocated += len(checks)
                continue
            for container, check in checks:
                severity = str(check.get("Severity") or "")
                if severity == "ignore":
                    continue
                issue_severity, level = POLARIS_SEVERITY_MAP.get(
                    severity, UNKNOWN_SEVERITY
                )
                rule_id = str(check["ID"])
                category = str(check.get("Category") or "")
                message = str(check.get("Message") or rule_id)
                details = [str(d) for d in (check.get("Details") or [])]
                text = f"{kind}/{name}"
                if container:
                    text += f" container {container}"
                text += f": {message}"
                if details:
                    text += " (" + "; ".join(details) + ")"
                rules.setdefault(
                    rule_id,
                    {
                        "id": rule_id,
                        "name": rule_id,
                        "shortDescription": {"text": message},
                        "properties": {
                            "tags": ["kubernetes"]
                            + ([category.lower()] if category else [])
                        },
                    },
                )
                for uri, line in places:
                    results.append(
                        {
                            "ruleId": rule_id,
                            "level": level,
                            "kind": "fail",
                            "message": {"text": text},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": line},
                                    }
                                }
                            ],
                            "properties": {
                                "issue_severity": issue_severity,
                                "tags": ["kubernetes"]
                                + ([category.lower()] if category else []),
                            },
                        }
                    )
        if unlocated:
            ASH_LOGGER.warning(
                f"polaris reported {unlocated} check failure(s) on objects that no "
                "regular YAML file in the scanned tree defines; they are not reported"
            )
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Polaris",
                            "informationUri": "https://github.com/FairwindsOps/polaris",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Keep ``issue_severity`` and the SARIF level in step; both set in conversion."""
        return sarif_report

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep Polaris's log out of ``self.errors``.

        Its log (logrus lines) can name paths from the scanned tree. The stream stays in
        the log file.
        """
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where Polaris's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (polaris was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). polaris' log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "polaris")
        if not found:
            ASH_LOGGER.warning(
                "polaris executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_polaris_plugins\"]' --tool polaris`."
            )
        return found is not None


__all__ = [
    "DANGER_EXIT_CODE",
    "POLARIS_SEVERITY_MAP",
    "PolarisScanner",
    "PolarisScannerConfig",
    "PolarisScannerConfigOptions",
]
