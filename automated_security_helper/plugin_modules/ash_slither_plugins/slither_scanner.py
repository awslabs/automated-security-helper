# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SlitherScanner: Solidity static analysis with Slither (crytic/slither).

What it runs
------------
``slither`` over the scan target, once for the source tree and once for the converted
tree. Slither compiles the Solidity it finds (it picks the project's own build tool,
such as Hardhat or Foundry, or plain ``solc``) and runs its detectors over the result.

Where the facts come from (read from Slither's source on 2026-11-19; the README
says only that SARIF exists, the flags are in ``slither/__main__.py``):

* ``--json <file>`` exports the results as JSON (``--json -`` is stdout). The file is
  ``{"success": bool, "error": ..., "results": {"detectors": [...]}}``
  (``slither/utils/output.py``, ``output_to_json``). Slither never overwrites an
  existing file there, so the report is deleted before each run.
* ``--sarif <file>`` exists, but ``output_to_sarif`` writes ``"level": "warning"`` on
  every result and carries impact only in ``security-severity``. ASH needs the SARIF
  level and ``issue_severity`` to agree per finding, so the plugin reads the JSON and
  builds the SARIF itself (``convert_slither_json``).
* ``--fail-none`` stops the exit code from carrying the finding count: by default
  (``--fail-pedantic``) any detection makes Slither exit -1 (255). With it a run that
  found things exits 0, and only a Slither error (``success`` false) still exits
  non-zero. ``success_exit_codes`` is therefore ``{0}``.
* ``--exclude-dependencies`` leaves out findings in code under ``node_modules`` and
  similar dependency directories.

Invocation: every option is one ``--flag=value`` token and the scan path follows
``--``, so no path is read as a flag. The working directory is the source directory,
so the source target is ``.`` and result paths come out source-relative.

Tree configuration
------------------
Measured on slither 0.11.6 with the pinned argv: a ``slither.config.json`` in the
working directory (Slither reads it when ``--config-file`` is not given) with
``detectors_to_exclude`` hid three of four findings, and a ``slither.db.json`` triage
database there hid all four. Both are files the scanned repository writes, so ASH
passes ``--config-file`` naming an empty ``{}`` file and ``--triage-database`` naming a
path that does not exist, both in its own results directory. With them the same four
findings came back. What stays: ``// slither-disable-next-line`` comments in the
Solidity source are honored and Slither offers no flag against them (register row
``silencing``).

A run that analyzed nothing
---------------------------
Measured on the same version: a clean analysis and a run that compiled nothing both
write ``{"success": true, "error": null, "results": {}}`` and exit 0, and the second is
what a bare directory gets when it has no supported project at its root and no ``.sol``
file directly in it (the sources sit in ``contracts/`` and the root is ``.``). The log
tells them apart: ``analyzed (N contracts with M detectors), K result(s) found`` with N
the number compiled. ``_require_a_contract_analyzed`` fails the scan when N is 0 or the
line is missing, so that run is an ERROR with the reason, never a clean scan.

Severity
--------
Slither's impact is High, Medium, Low, Informational or Optimization. The mapping is
``SLITHER_IMPACT_MAP``: High -> HIGH / error, Medium -> MEDIUM / warning, Low -> LOW /
note, Informational and Optimization -> INFO / none. High is HIGH and not CRITICAL:
Slither's High detectors (reentrancy, unprotected selfdestruct, arbitrary send) are
patterns the tool believes are exploitable, not confirmed exploits, and its confidence
is a separate field kept in the result properties. A result with no impact is MEDIUM; an
impact this plugin does not know is HIGH, the more severe reading.

Findings without a location
---------------------------
A Slither finding whose first element has no source mapping cannot be placed in a
file. It is counted and reported in the log at WARNING, and left out of the SARIF.

Licensing
---------
Slither is AGPL-3.0. ASH never installs it: this plugin declares no install command
and no download, and a scan reports the scanner MISSING with the install line when
``slither`` is not on PATH. The operator installs it (for example
``uv tool install slither-analyzer``) and accepts its license.

What running it means for the scanned tree
------------------------------------------
Given a directory, Slither hands the build to the project's framework (``npx hardhat
compile``, ``forge build``), which executes the repository's own build configuration,
and solc-select may fetch a compiler. List this module only for trees you are willing
to build. The scanner declares the strict sandbox default, so a sandboxed run has no
network and a build that needs one fails.

Nothing to scan
---------------
A tree with no ``.sol`` file is a no-op: the scanner is SKIPPED with a reason, and
Slither is not started.
"""

from __future__ import annotations

import logging
import os
import re
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
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

#: What ``nothing_to_scan_reason`` and the skip in ``scan`` say.
NO_SOLIDITY_FILES = "no Solidity (.sol) file in the scan target"

#: Slither's closing summary line, written to stderr after every analysis:
#: ``<target> analyzed (N contracts with M detectors), K result(s) found``. A run that
#: compiled nothing prints ``No contract was analyzed`` before it, with N = 0.
_ANALYZED_SUMMARY = re.compile(
    r"analyzed \((\d+) contracts? with (\d+) detectors?\), (\d+) result\(s\) found"
)

#: The line a missing scanner reports.
INSTALL_HINT = (
    "slither is not installed. It is AGPL-3.0 licensed, so ASH does not install it: "
    "install it yourself (for example `uv tool install slither-analyzer`) and make "
    "sure `slither` is on PATH."
)

#: Directories not walked when looking for Solidity files. Files under them are
#: dependencies, which the scan passes ``--exclude-dependencies`` for.
_SKIPPED_DIRECTORIES = frozenset({".git", "node_modules"})

#: Slither impact (lower-cased) -> (ASH issue_severity, SARIF level). See "Severity" in
#: the module docstring.
SLITHER_IMPACT_MAP: Dict[str, Tuple[str, str]] = {
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("LOW", "note"),
    "informational": ("INFO", "none"),
    "optimization": ("INFO", "none"),
}
#: A result that carries no impact.
MISSING_IMPACT_RATING: Tuple[str, str] = ("MEDIUM", "warning")
#: An impact not in the table: the more severe reading.
UNKNOWN_IMPACT_RATING: Tuple[str, str] = ("HIGH", "error")

SLITHER_INFORMATION_URI = "https://github.com/crytic/slither"


def holds_solidity(root: Path) -> bool:
    """Whether ``root`` holds a regular ``.sol`` file outside the skipped directories.

    Links are not followed: a link to a directory is not walked and a link to a file
    is not counted, so a link out of the tree cannot make the scan look non-empty.
    """
    root = Path(root)
    if root.is_file():
        return root.suffix == ".sol"
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        subdirectories[:] = [d for d in subdirectories if d not in _SKIPPED_DIRECTORIES]
        for name in names:
            if name.endswith(".sol") and not os.path.islink(
                os.path.join(directory, name)
            ):
                return True
    return False


def _rating(impact: Any) -> Tuple[str, str]:
    if impact is None or impact == "":
        return MISSING_IMPACT_RATING
    if isinstance(impact, str):
        return SLITHER_IMPACT_MAP.get(impact.strip().lower(), UNKNOWN_IMPACT_RATING)
    return UNKNOWN_IMPACT_RATING


def _location(detector: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The SARIF location of a detector result's first element, or None."""
    elements = detector.get("elements")
    if not isinstance(elements, list) or not elements:
        return None
    first = elements[0]
    mapping = first.get("source_mapping") if isinstance(first, dict) else None
    if not isinstance(mapping, dict):
        return None
    uri = mapping.get("filename_relative") or mapping.get("filename_absolute")
    if not isinstance(uri, str) or not uri:
        return None
    physical: Dict[str, Any] = {
        "artifactLocation": {"uri": uri.replace("\\", "/")},
    }
    lines = mapping.get("lines")
    if isinstance(lines, list) and lines and all(isinstance(n, int) for n in lines):
        region: Dict[str, Any] = {"startLine": min(lines)}
        if max(lines) != min(lines):
            region["endLine"] = max(lines)
        physical["region"] = region
    return {"physicalLocation": physical}


def convert_slither_json(document: Any) -> Tuple[Dict[str, Any], int]:
    """Slither ``--json`` output -> (SARIF 2.1.0 dict, findings left out for no location).

    Raises ``ScannerError`` for a document that is not a Slither result object, one
    Slither marked as failed (``success`` false, with its ``error``), or one without
    ``results``: none of those is a clean scan.
    """
    if not isinstance(document, dict):
        raise ScannerError("slither's JSON output is not a result object")
    if document.get("success") is False:
        error = document.get("error")
        raise ScannerError(
            "slither reported that it failed"
            + (f": {str(error)[:300]}" if error else "")
        )
    results = document.get("results")
    if not isinstance(results, dict):
        raise ScannerError("slither's JSON output has no results object")
    detectors = results.get("detectors", [])
    if not isinstance(detectors, list):
        raise ScannerError("slither's JSON output has a malformed detectors list")

    rules: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []
    unplaced = 0
    for detector in detectors:
        if not isinstance(detector, dict):
            raise ScannerError(
                "slither's JSON output has a detector that is not an object"
            )
        location = _location(detector)
        if location is None:
            unplaced += 1
            continue
        check = str(detector.get("check") or "slither-finding")
        severity, level = _rating(detector.get("impact"))
        if check not in rules:
            rules[check] = {
                "id": check,
                "name": check,
                "shortDescription": {"text": check},
                "helpUri": str(detector.get("reference") or SLITHER_INFORMATION_URI),
                "properties": {"tags": ["solidity", "security"]},
            }
        properties: Dict[str, Any] = {
            "issue_severity": severity,
            "tags": ["solidity", "security"],
        }
        if detector.get("confidence"):
            properties["slither_confidence"] = str(detector["confidence"])
        result: Dict[str, Any] = {
            "ruleId": check,
            "level": level,
            "kind": "fail",
            "message": {"text": str(detector.get("description") or check).strip()},
            "locations": [location],
            "properties": properties,
        }
        if detector.get("id"):
            result["partialFingerprints"] = {"slither/v1": str(detector["id"])}
        sarif_results.append(result)

    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Slither",
                        "informationUri": SLITHER_INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return sarif, unplaced


class SlitherScannerConfigOptions(ScannerOptionsBase):
    """No option of its own: severity_threshold, scan_timeout and offline come from
    the base. Nothing here lets the scanned tree hide a finding."""


class SlitherScannerConfig(ScannerPluginConfigBase):
    name: Literal["slither"] = "slither"
    enabled: bool = True
    options: Annotated[
        SlitherScannerConfigOptions,
        Field(description="Configure the slither scanner"),
    ] = SlitherScannerConfigOptions()


@ash_scanner_plugin
class SlitherScanner(ScannerPluginBase[SlitherScannerConfig]):
    """Solidity static analysis over the scan target using Slither."""

    #: Not Python-only in ASH's sense: the operator installs a separate tool, and a
    #: Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    #: The facets register row (base/scanner_facets.py). Native fields name
    #: Slither's ``--json`` document (captured at
    #: tests/test_data/scanners/slither/captured/positive.json), which
    #: ``convert_slither_json`` turns into the SARIF the committed
    #: ``positive.sarif`` fixture holds.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results.detectors[] "check" (e.g. reentrancy-eth)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results.detectors[] "impact" through SLITHER_IMPACT_MAP '
            "(High/Medium/Low/Informational/Optimization), written as the SARIF "
            'level and the result property "issue_severity"',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="detectors[].elements[0].source_mapping.filename_relative",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="detectors[].elements[0].source_mapping.lines "
            "(min and max become startLine and endLine)",
        ),
        column=FacetDecl(
            state=FacetState.DROPPED,
            native_field="detectors[].elements[0].source_mapping.starting_column "
            "and ending_column",
            reason="convert_slither_json writes whole-line regions only; the "
            "columns are in the JSON and are not copied",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results.detectors[] "description"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="a finding names a contract element (function, variable, "
            "pragma) in Solidity source, not a deployable resource; the "
            "adapter writes a file and line region only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="a finding names a contract element in source, not a "
            "deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="Slither findings carry no package identity",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="Slither findings carry no package identity",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="Slither findings carry no package identity",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="Slither detectors carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the --json result carries no CWE field",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results.detectors[] "id" (a sha256 of the finding), '
            'written as partialFingerprints["slither/v1"]',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="Slither's JSON carries no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="Slither's JSON carries no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="source_mapping carries offsets and line numbers, not the "
            "matched text, and the adapter reads no source file",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='results.detectors[] "reference" (the detector '
            "documentation URL)",
            reason="the adapter writes it as the rule helpUri, which the flat "
            "row does not read (it reads result relatedLocations)",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="rule and result tags solidity and security, written "
            "by the adapter",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results.detectors[] "confidence", written as the '
            'result property "slither_confidence"',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="slither",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "slither_scanner.py offline_strategy and sandbox_requirements; "
                    "the detectors ship in the tool. A build that needs solc or npm "
                    "packages can reach the network under the project's own build "
                    "configuration, which ASH does not control (module header)"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="`slither` over the scan root, which compiles through the "
                "project's own framework (hardhat, foundry) or, for a bare "
                "directory, the .sol files directly in it; staged_scope_patterns "
                "is *.sol",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="AGPL-3.0: ASH declares no install command and no download, so "
                "the operator installs slither-analyzer; a scan without it is "
                "MISSING with the install line",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="Slither's own impact scale is mapped one-to-one "
                "(SLITHER_IMPACT_MAP); Informational and Optimization share INFO",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="`// slither-disable-next-line <detector>` and the "
                        "start/end forms in the Solidity source",
                        cite="measured on slither 0.11.6: a disable-next-line "
                        "comment above the call removed its reentrancy-eth finding "
                        "and left the others (a repository can hide findings with "
                        "it; Slither offers no flag to ignore the comments)",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="slither.config.json (detectors_to_exclude and the "
                        "other options) and the slither.db.json triage database "
                        "in the working directory",
                        cite="slither_scanner.py module header (Tree configuration): "
                        "ASH passes --config-file and --triage-database pointing "
                        "into its own results directory; measured on slither "
                        "0.11.6 that the two files hid findings without them",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_NATIVE,
                note="the detector id is a sha256 Slither computes over the finding, "
                'written as partialFingerprints["slither/v1"]',
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no option of its own: severity_threshold, "
                "scan_timeout and offline come from the base; Slither's config "
                "file is replaced by an empty one so the tree cannot set options",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="ASH passes --fail-none, so a run that found things exits "
                "0; the default (--fail-pedantic) exits 255 on any detection",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_slither_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="a .sol file is needed (nothing_to_scan_reason skips a tree "
                "without one); a project root with no supported framework and no "
                ".sol file directly in it analyzes no contract and the scan fails "
                "instead of reading clean",
            ),
        )
    )

    # The detectors are bundled with Slither. Compiling a project can need the
    # network (solc downloads, npm); the strict sandbox below grants none.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # --fail-none makes a run that found things exit 0; see the module docstring.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default: no network, baseline environment only.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()
    staged_scope_patterns: ClassVar[Optional[Tuple[str, ...]]] = ("*.sol",)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SlitherScannerConfig()
        self.command = "slither"
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _build_arguments; ToolArgs stays empty so nothing
        # from the base resolver adds a token Slither would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # No custom_install_commands, dependencies or uv tool: AGPL-3.0, user-side install
    # only. See "Licensing" in the module docstring.

    def validate_plugin_dependencies(self) -> bool:
        if super().validate_plugin_dependencies():
            return True
        if not self.dependency_unavailable_reason:
            self.dependency_unavailable_reason = INSTALL_HINT
        ASH_LOGGER.warning(self.dependency_unavailable_reason)
        return False

    def nothing_to_scan_reason(self) -> Optional[str]:
        """The reason when neither the source tree nor a converted tree holds a .sol file."""
        if self.context is None:
            return None
        trees = [Path(self.context.source_dir)]
        work_dir = Path(self.context.work_dir)
        if work_dir.is_dir() and any(work_dir.rglob("*.*")):
            trees.append(work_dir)
        for tree in trees:
            if holds_solidity(tree):
                return None
        return NO_SOLIDITY_FILES

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("SlitherScanner has no plugin context")
        return Path(self.context.source_dir)

    def _scan_path(self, target: Path) -> str:
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    @staticmethod
    def _config_path(results_file: Path) -> Path:
        """The empty config file passed as ``--config-file`` (see "Tree configuration")."""
        return results_file.parent / "slither-config.json"

    @staticmethod
    def _triage_path(results_file: Path) -> Path:
        """The triage database path passed as ``--triage-database``; never created."""
        return results_file.parent / "slither-triage.db.json"

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        return [
            self.command or "slither",
            f"--json={results_file.as_posix()}",
            f"--config-file={self._config_path(results_file).as_posix()}",
            f"--triage-database={self._triage_path(results_file).as_posix()}",
            "--fail-none",
            "--exclude-dependencies",
            "--",
            self._scan_path(target),
        ]

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """The template scan, except that a tree with no .sol file never starts Slither."""
        if Path(target).is_dir() and any(Path(target).iterdir()):
            if not holds_solidity(Path(target)):
                self.exit_code = 0
                self.start_time = None
                self.end_time = None
                self.output = []
                self._reset_errors()
                self._nothing_scanned_reason = (
                    f"SlitherScanner skipped the {target_type} target: "
                    f"{NO_SOLIDITY_FILES}"
                )
                self._plugin_log(
                    f"{self._nothing_scanned_reason}. Not running slither.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return True
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """The argv and report path for one Slither run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by ASH, so it is
        not translated into Slither flags.
        """
        if self.results_dir is None:
            raise ScannerError("SlitherScanner has no results directory")
        # One instance scans source and then converted; keep the worst code per target.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "slither.json")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # Slither does not overwrite an existing --json file, and a report left by an
        # earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        # The scanned tree's own slither.config.json and slither.db.json are replaced:
        # an empty config, and a triage database path that does not exist.
        self._triage_path(results_file).unlink(missing_ok=True)
        with open_for_write(self._config_path(results_file)) as handle:
            handle.write("{}\n")
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _require_a_contract_analyzed(self, results_file: Path) -> None:
        """Refuse a run that compiled nothing.

        Slither's JSON is ``{"success": true, "results": {}}`` both for a clean
        analysis and for one that analyzed no contract (a directory with no
        supported project and no ``.sol`` file directly in it), and exits 0 in both,
        so the document cannot tell them apart. The summary line in the log can.
        """
        log = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        try:
            text = log.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ScannerError(
                "slither's log could not be read, so whether it analyzed any "
                f"contract is unknown ({exc.__class__.__name__})"
            ) from exc
        summaries = _ANALYZED_SUMMARY.findall(text)
        if not summaries:
            raise ScannerError(
                "slither's log has no analysis summary line, so whether it "
                "analyzed any contract is unknown"
            )
        if int(summaries[-1][0]) == 0:
            raise ScannerError(
                "slither analyzed 0 contracts, so this is not a clean scan: the "
                "scan root has no project it can build (hardhat, foundry, truffle, "
                "...) and no .sol file directly in it"
            )

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse a run Slither did not finish, then turn its JSON into SARIF."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"slither exited {self.exit_code}; with --fail-none it exits 0 "
                "whether or not it finds anything, so this run failed"
            )
        self._require_a_contract_analyzed(results_file)
        document = super()._read_results_file(results_file)
        if document is None:
            return None
        sarif, unplaced = convert_slither_json(document)
        if unplaced:
            self._plugin_log(
                f"{unplaced} slither finding(s) had no source location and are not "
                "in the report",
                level=logging.WARNING,
            )
        return sarif

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Keep Slither's stderr out of ``self.errors``.

        Its compile errors quote lines of the scanned tree. The stream stays in the log
        file.
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
        """The failure and where Slither's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (slither was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). slither's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )


__all__ = [
    "INSTALL_HINT",
    "NO_SOLIDITY_FILES",
    "SLITHER_IMPACT_MAP",
    "SlitherScanner",
    "SlitherScannerConfig",
    "SlitherScannerConfigOptions",
    "convert_slither_json",
    "holds_solidity",
]
