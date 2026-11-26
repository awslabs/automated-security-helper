# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SBOM generation over the scan target's files using cdxgen (CycloneDX Generator).

cdxgen is an inventory tool, like syft: it lists the components a tree uses and
reports no findings. Its output is a CycloneDX document, not SARIF, so this scanner
overrides ``scan()`` and returns a ``CycloneDXReport`` the way the builtin syft
scanner does, instead of filling in the template's ``_execute_scan``.

What was read from cdxgen's CLI documentation (docs/CLI.md in the CycloneDX/cdxgen
repository) and not run on this host:

- ``--output`` is the output file (default ``bom.json``).
- ``--spec-version`` takes 1.6, 1.7 or 2.0 and defaults to 1.7. ASH models 1.6
  (``CycloneDXReport``), so ``--spec-version=1.6`` is always passed.
- ``--install-deps`` defaults to true: cdxgen installs dependencies of the scanned
  project, which runs the project's package manager over code the tree controls.
  ``--no-install-deps`` is always passed.
- Exit status: 0 success, 1 generic failure, 4 and 5 only for ``--introspect``
  runs, which ASH does not use. Only 0 is accepted.

Severity: there are no findings, so there is no SARIF level and no
``issue_severity`` to disagree. The components are inventory (INFO), as syft's are.

Working directory: cdxgen can read a ``.cdxgenrc`` or a ``package.json`` section
from its working directory, so it runs from outside the scanned tree
(``cwd_outside_scanned_tree``) and is given the scan path absolute.

Offline: with ``--no-install-deps`` ASH makes no registry call on cdxgen's behalf;
the sandbox grants no network (see ``sandbox_requirements``).
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, ClassVar, List, Literal, Set

from pydantic import Field, ValidationError, model_validator

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import PluginDependency
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.path_trust import cwd_outside_scanned_tree
from automated_security_helper.core.enums import (
    OfflineStrategy,
    PackageManager,
    ScannerToolType,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The npm package that provides the ``cdxgen`` command, and the release ASH installs.
CDXGEN_NPM_PACKAGE = "@cyclonedx/cdxgen"
CDXGEN_VERSION = "12.9.2"

#: The CycloneDX version cdxgen is asked to write; ``CycloneDXReport`` models 1.6.
CYCLONEDX_SPEC_VERSION = "1.6"

#: The upstream license of record for the register (opsf requires a source
#: citation): the LICENSE of the pinned npm package, the same bytes as the
#: repository's LICENSE at the commit the v12.9.2 tag names.
LICENSE_CITATION = (
    "Apache-2.0 (source: the LICENSE file and package.json of the "
    "@cyclonedx/cdxgen 12.9.2 npm package, LICENSE sha256 "
    "b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1, the same "
    "bytes as the repository's LICENSE at the v12.9.2 tag commit "
    "fbe21f580e799ae8182ad0a64729d6cfb4216682; read 2026-11-26; no license or "
    "service gate, ASH installs it from npm and does not redistribute it)"
)

#: Platform and architecture pairs the npm package runs on (Node.js decides).
INSTALL_PLATFORMS = {
    "linux": ("amd64", "arm64"),
    "darwin": ("amd64", "arm64"),
    "windows": ("amd64", "arm64"),
}


class CdxgenScannerConfigOptions(ScannerOptionsBase):
    project_type: Annotated[
        List[str],
        Field(
            description=(
                "Project types passed to cdxgen as one --type=<value> each (for "
                "example js, python, java). Empty lets cdxgen detect the types."
            ),
        ),
    ] = []
    exclude: Annotated[
        List[IgnorePathWithReason],
        Field(
            description=(
                "Glob patterns cdxgen skips, each passed as one --exclude=<glob>."
            ),
        ),
    ] = []


class CdxgenScannerConfig(ScannerPluginConfigBase):
    name: Literal["cdxgen"] = "cdxgen"
    enabled: bool = True
    options: Annotated[
        CdxgenScannerConfigOptions,
        Field(description="Configure the cdxgen scanner"),
    ] = CdxgenScannerConfigOptions()


@ash_scanner_plugin
class CdxgenScanner(ScannerPluginBase[CdxgenScannerConfig]):
    """CdxgenScanner generates a CycloneDX SBOM using cdxgen."""

    display_name = "cdxgen"
    docs_summary = "Software inventory"
    covers = ("SBOM generation",)

    #: The facets register row (base/scanner_facets.py). cdxgen writes a CycloneDX
    #: document and no findings, and the document bypasses the flat findings path, so
    #: every facet is n/a (component name and version live in the document itself).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no rule id",
        ),
        severity=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no severity",
        ),
        file_path=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist; component evidence locations are inventory, not a finding location",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no line range",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no column",
        ),
        message=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no message",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="no findings exist; the SBOM names packages (package identity), not infrastructure resources, and writes no ash_resource_id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="no findings exist; CycloneDX component types (library, application) are package kinds, not resource types",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="the CycloneDX components[].name values are returned in the "
            "document, which bypasses the flat findings path; no Result carries "
            "them, so there is nothing for the register to observe",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="the CycloneDX components[].version values are returned in the "
            "document, which bypasses the flat findings path; no Result carries "
            "them, so there is nothing for the register to observe",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the CycloneDX document is passed through whole; no per-finding package path is written",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist; cdxgen inventories components and matches no advisories here",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist; cdxgen inventories components and matches no advisories here",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist to fingerprint",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no remediation",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no snippet",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no references",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no findings exist, so no tags",
        ),
        extras=FacetDecl(
            state=FacetState.NA,
            reason="SBOM scanner: no SARIF property bag; the CycloneDX document is passed through whole outside the flat path",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py), checked
    #: against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="cdxgen",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "cdxgen_scanner.py module header (--no-install-deps) and "
                    "sandbox_requirements: the strict default grants no network"
                ),
                unconfirmed=(
                    "whether cdxgen makes any other registry or license lookup "
                    "under --no-install-deps; a sample run with the network "
                    "blocked would settle it"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.CYCLONEDX,),
                side_reports=(),
                non_finding_artifacts=("CycloneDXReport (the SBOM)",),
                consumed_by_deviation=(
                    "no SARIF Result exists; the SBOM is returned as a "
                    "CycloneDXReport outside the flat findings path"
                ),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.PACKAGE_INVENTORY,),
                tool_type=ScannerToolType.SBOM,
                selection=(
                    "the whole directory; project types are detected by cdxgen "
                    "or set with options.project_type"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("node",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for cdxgen.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note=(
                    "an npm package (@cyclonedx/cdxgen) installed through the "
                    "npm package manager on every platform Node.js runs on; ASH "
                    "downloads no pinned binary for it"
                ),
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NOT_APPLICABLE,
                note="an SBOM has no findings",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason=(
                    "cdxgen produces an SBOM, not findings; there is nothing to silence"
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.NOT_APPLICABLE,
                note="no findings to identify",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (project_type, exclude); no rules surface",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics=(
                    "a completed run exits 0; 1 is a failure and 4 and 5 are "
                    "--introspect only, which ASH does not use"
                ),
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_cdxgen_plugins in ash_plugin_modules",),
                upstream_license=LICENSE_CITATION,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NODE_RUNTIME,),
                note="cdxgen is a Node.js program; a directory is the input",
            ),
        )
    )

    #: cdxgen is a Node.js program; a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # An SBOM has no "findings found" exit code; 1 is a failure.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default: no network, baseline environment only.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context):
        if self.config is None:
            self.config = CdxgenScannerConfig()
        self.command = "cdxgen"
        self.tool_type = ScannerToolType.SBOM
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_install_commands(self) -> "CdxgenScanner":
        """Install the pinned release from npm, for every platform Node.js runs on."""
        for platform, architectures in INSTALL_PLATFORMS.items():
            for arch in architectures:
                self.dependencies.setdefault(platform, {})[arch] = [
                    PluginDependency(
                        name=CDXGEN_NPM_PACKAGE,
                        version=CDXGEN_VERSION,
                        package_manager=PackageManager.NPM,
                    )
                ]
        return self

    def _options(self) -> CdxgenScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, CdxgenScannerConfigOptions):
            return options
        return CdxgenScannerConfigOptions()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full cdxgen argv. Options are single ``--flag=value`` tokens."""
        args: List[str] = [
            self.command or "cdxgen",
            f"--output={results_file.as_posix()}",
            f"--spec-version={CYCLONEDX_SPEC_VERSION}",
            "--no-install-deps",
        ]
        options = self._options()
        for project_type in options.project_type:
            args.append(f"--type={project_type}")
        for item in options.exclude:
            args.append(f"--exclude={item.path}")
        # ASH's own output directories inside the target would be inventoried too.
        for relative in self._ash_output_dirs_inside(target):
            args.append(f"--exclude=**/{Path(relative).as_posix()}/**")
        args.append(target.as_posix())
        return args

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub: CdxgenScanner overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CdxgenScannerConfig | None = None,
    ) -> CycloneDXReport | bool:
        """Run cdxgen over ``target`` and return its SBOM.

        Returns True for an empty or missing target (nothing to inventory) and False
        when the scanner cannot run. Raises ScannerError when cdxgen fails, times
        out, or writes something that is not CycloneDX 1.6.
        """
        self.exit_code = 0
        self.output = []
        self._reset_errors()
        if self._target_is_empty(target):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self.start_time = None
            self._post_scan(target=target, target_type=target_type)
            return True

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        refusal: ScannerError | None = None
        try:
            target = Path(os.path.abspath(target))
            results_dir = Path(os.path.abspath(self.results_dir)).joinpath(target_type)
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("cdxgen.cdx.json")
            # A report left by an earlier run must not be read as this run's.
            results_file.unlink(missing_ok=True)
            final_args = self._build_arguments(target, results_file)
            timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=results_dir,
                cwd=cwd_outside_scanned_tree(
                    target,
                    results_dir=results_dir,
                    source_dir=self.context.source_dir,
                    config=getattr(self.context, "config", None),
                ),
                timeout=timeout,
            )
            self._post_scan(target=target, target_type=target_type)
            try:
                self._refuse_flagged_response(response, timeout)
            except ScannerError as flagged:
                refusal = flagged
                raise
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            try:
                with open(results_file, mode="r", encoding="utf-8") as handle:
                    document = json.load(handle)
            except (OSError, ValueError) as exc:
                raise ScannerError(
                    f"cdxgen wrote no readable JSON report ({exc.__class__.__name__})"
                )
            try:
                return CycloneDXReport.model_validate(document)
            except ValidationError as exc:
                # The count only: the text would quote the document's values.
                raise ScannerError(
                    "cdxgen wrote a report that is not CycloneDX 1.6 ASH can read "
                    f"({exc.error_count()} validation error(s))"
                )
        except Exception as exc:
            self.end_time = datetime.now(timezone.utc)
            if exc is refusal:
                raise
            failure = f"{self.__class__.__name__} scan failed: {exc}"
        raise ScannerError(failure)

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "cdxgen")
        if not found:
            ASH_LOGGER.warning(
                "cdxgen executable not found in PATH (it needs Node.js). Install it "
                "with `ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_cdxgen_plugins\"]' --tool cdxgen`."
            )
        return found is not None


__all__ = [
    "CdxgenScanner",
    "CdxgenScannerConfig",
    "CdxgenScannerConfigOptions",
]
