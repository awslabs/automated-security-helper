# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BinSkim community scanner plugin: binary hardening checks over PE, ELF and Mach-O files.

What it runs
------------
``BinSkim analyze`` over the scan target with ``--recurse``. BinSkim (Microsoft, MIT
license) inspects compiled binaries for missing hardening (ASLR, DEP, stack protector,
control-flow guard, RELRO, and similar). Every rule is a ``BA####`` id.

Flags (read from BinSkim's ``AnalyzeOptions.cs`` and the sarif-sdk
``AnalyzeOptionsBase.cs``; see the plugin README for the sources):

* ``--output=<file>`` (short ``-o``) writes the SARIF log to a file.
* ``--recurse=true`` descends into the target's subdirectories.
* ``--level=Error;Warning;Note`` and ``--kind=Fail`` select the results written. The
  tool's own default is Error and Warning only, so ``Note`` is requested explicitly.
* ``--quiet=true`` suppresses console output.
* ``--disable-telemetry=true`` turns BinSkim's telemetry off.
* ``--ignorePdbLoadError=true`` keeps a PDB that cannot be loaded from ending the run.
* No ``--config`` is passed, so a policy file in the scanned tree is never read, and
  nothing here points BinSkim at a symbol server (``--sympath``), so it makes no
  network call.

Each option is one ``--flag=value`` token and the scan path follows ``--``, so no path
is read as a flag. The path is passed absolute; report URIs are made source-relative
in ``_post_process_sarif``.

Targets
-------
BinSkim reads Windows PE, Linux ELF and macOS Mach-O files. ``nothing_to_scan_reason``
looks for those magic numbers in the tree, so a tree with no binary is SKIPPED rather
than PASSED or failed.

Severity
--------
SARIF ``error`` is HIGH, ``warning`` is MEDIUM and ``note`` is LOW. They are not
CRITICAL: a missing mitigation is a hardening gap, not a vulnerability by itself. A
result with no level is MEDIUM. A result whose kind is not ``fail`` (BinSkim emits
``pass`` and ``notApplicable`` results for rules that held) is dropped. ``issue_severity``
and the SARIF level always agree.

Exit status
-----------
BinSkim exits 0 on a completed run, finding results or not (its user guide: "A
successful run can still contain findings"). ``--rich-return-code`` is not passed, so
any other code is a tool or configuration failure and fails the scan even when a report
is on disk.

Offline
-------
Rules are compiled into the tool and no symbol server is configured, so no network is
needed.

Sandbox
-------
The strict default: no network, baseline environment. Nothing here needs more.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import Field, model_validator

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
from automated_security_helper.core.exceptions import (
    ScannerError,
    ToolNotProvisionableError,
)
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: SARIF level -> (ASH severity, level written back). One row per level BinSkim emits.
BINSKIM_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
}

#: Severity of a result that arrives with no level, and its level.
DEFAULT_SEVERITY: Tuple[str, Level] = ("MEDIUM", Level.warning)

#: Leading bytes of the formats BinSkim reads: PE (``MZ``), ELF, and the Mach-O
#: magic numbers (32/64 bit, both byte orders, and fat binaries).
BINARY_MAGIC: Tuple[bytes, ...] = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)

#: The most files looked at when deciding whether the tree holds a binary.
MAX_FILES_PROBED = 50000

_SKIPPED_DIRS = {".git", ".hg", ".svn", "node_modules"}


class BinskimScannerConfigOptions(ScannerOptionsBase):
    """No options beyond the base ones (``severity_threshold``, ``scan_timeout``,
    ``offline``). BinSkim's policy file and symbol path would let the scanned tree or
    the network change what is reported, so ASH exposes neither."""


class BinskimScannerConfig(ScannerPluginConfigBase):
    name: Literal["binskim"] = "binskim"
    enabled: bool = True
    options: Annotated[
        BinskimScannerConfigOptions,
        Field(description="Configure the binskim scanner"),
    ] = BinskimScannerConfigOptions()


def _looks_like_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return any(head.startswith(magic) for magic in BINARY_MAGIC)


def tree_holds_a_binary(root: Path) -> bool:
    """True when a PE, ELF or Mach-O file is found under ``root`` (links not followed)."""
    probed = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIPPED_DIRS]
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            probed += 1
            if probed > MAX_FILES_PROBED:
                return True  # cannot tell; let BinSkim decide
            if _looks_like_binary(path):
                return True
    return False


@ash_scanner_plugin
class BinskimScanner(ScannerPluginBase[BinskimScannerConfig]):
    """Binary hardening analysis over the scan target's PE, ELF and Mach-O files."""

    python_only: ClassVar[bool | None] = False
    # Rules are compiled in and no symbol server is configured.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # Findings do not change BinSkim's exit code; see "Exit status" above.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default (no network, baseline environment).
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). BinSkim's output has not
    #: been read from a real run (see tests/test_data/scanners/binskim/README.md),
    #: so only the SARIF fields every BinSkim result is documented to carry are
    #: MAPPED; every other cell is n/a with "a sample run would settle it".
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result.ruleId (BA#### rule id)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result.level (error/warning/note), mapped by "
            "BINSKIM_LEVEL_MAP",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result.locations[0].physicalLocation.artifactLocation.uri "
            "(the analyzed binary)",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="a binary has no source lines; output not read for regions; "
            "a sample run would settle it",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="a binary has no source columns",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result.message.text",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a compiled binary file, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a compiled binary file, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="BinSkim reports on files, not packages; output not read; a "
            "sample run would settle it",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="BinSkim reports on files, not packages; output not read; a "
            "sample run would settle it",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="BinSkim reports on files, not packages; output not read; a "
            "sample run would settle it",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="hardening checks carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="hardening findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a binary has no source snippet",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="BinSkim writes no tags; the adapter's constant binary-hardening "
            "and security result tags are not read from the tool",
        ),
        extras=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py). The
    #: runtime is USER_INSTALLED_CLI until the integration lane pins a release
    #: in utils/tool_downloads.py; it then becomes a PINNED_BINARY.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="binskim",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "binskim_scanner.py: rules compiled into the tool, "
                    "--disable-telemetry=true, no --sympath"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection=(
                    "every PE, ELF or Mach-O file under the target "
                    "(BinSkim analyze --recurse; nothing_to_scan_reason probes magic bytes)"
                ),
                covers_note="a community scanner; it declares no covers display string",
                tool_type_note=(
                    "no TargetKind names compiled binaries; SOURCE_CODE is the "
                    "closest kind a SAST scanner may claim. A binary target kind "
                    "belongs to the target-kind vocabulary work"
                ),
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
                note="BinSkim has no pinned release in utils/tool_downloads.py yet, "
                "so ASH provisions nothing for it",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="SARIF error, warning and note map to HIGH, MEDIUM and LOW "
                "(BINSKIM_LEVEL_MAP)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="no --config policy file is passed, so nothing in the "
                "scanned tree can silence a rule; ASH suppressions are the surface "
                "this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="output not read; a sample run would settle it",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options beyond the base ones; no policy file "
                "or symbol path is exposed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 on a completed run, findings or not; any other code "
                "fails the scan even when a report is on disk",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_binskim_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="a PE, ELF or Mach-O file in the tree; a tree with none is "
                "SKIPPED by nothing_to_scan_reason",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = BinskimScannerConfig()
        self.command = "BinSkim"
        self.subcommands = ["analyze"]
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _build_arguments; nothing from the base resolver
        # may add a token BinSkim would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "BinskimScanner":
        """Install from the pinned release in ``utils/tool_downloads.py``, once pinned.

        ``utils/tool_downloads.py`` has no BinSkim table until the integration lane
        adds one (see the plugin README, "Central registration owed"). Until then
        ``pinned_tool_install_commands`` raises ``ToolNotProvisionableError``, and
        raising from here would make the scanner impossible to construct. So the
        table is left empty: ASH provisions nothing, the scanner reports the tool
        missing, and the remedy (install BinSkim yourself) is named in the log.
        """
        try:
            self.custom_install_commands.update(pinned_tool_install_commands("binskim"))
        except ToolNotProvisionableError:
            pass
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("BinskimScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """A reason when neither the source nor the converted tree holds a binary."""
        if self.context is None:
            return None
        roots = [Path(self.context.source_dir)]
        work_dir = getattr(self.context, "work_dir", None)
        if work_dir:
            roots.append(Path(work_dir))
        for root in roots:
            if root.exists() and tree_holds_a_binary(root):
                return None
        return "the scan target holds no PE, ELF or Mach-O file for BinSkim to analyze"

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        return [
            self.command or "BinSkim",
            *self.subcommands,
            f"--output={results_file.as_posix()}",
            "--recurse=true",
            "--level=Error;Warning;Note",
            "--kind=Fail",
            "--quiet=true",
            "--disable-telemetry=true",
            "--ignorePdbLoadError=true",
            "--",
            Path(target).absolute().as_posix(),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one BinSkim run."""
        if self.results_dir is None:
            raise ScannerError("BinskimScanner has no results directory")
        # The base keeps the worst exit code across the source and converted runs.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "binskim.sarif")
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
        """Refuse the report of a run that did not exit with an accepted code."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"BinSkim exited {self.exit_code}; it exits 0 on a completed run, "
                "so this run failed"
            )
        return super()._read_results_file(results_file)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep BinSkim's stderr out of ``self.errors``."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    @staticmethod
    def _relative_uri(uri: str, target: Path) -> str:
        """``uri`` relative to ``target`` when it lies under it, else unchanged."""
        raw = uri
        if raw.startswith("file://"):
            raw = raw[len("file://") :]
            if len(raw) > 2 and raw[0] == "/" and raw[2] == ":":
                raw = raw[1:]  # file:///C:/x
        try:
            return (
                Path(os.path.normpath(raw))
                .relative_to(Path(target).absolute())
                .as_posix()
            )
        except ValueError:
            return uri

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Keep failures only, rate each result, and make URIs source-relative."""
        for run in sarif_report.runs or []:
            if run.results:
                run.results = [
                    r
                    for r in run.results
                    if r.kind is None or getattr(r.kind, "value", r.kind) == "fail"
                ]
        for result in sarif_report.get_all_results():
            level_text = getattr(result.level, "value", result.level)
            severity, level = BINSKIM_LEVEL_MAP.get(
                str(level_text) if level_text else "", DEFAULT_SEVERITY
            )
            result.level = level
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("binary-hardening", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010

            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                if artifact is not None and artifact.uri:
                    artifact.uri = self._relative_uri(artifact.uri, target)
        return sarif_report

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where BinSkim's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (BinSkim was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). BinSkim's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "BinSkim")
        if not found:
            ASH_LOGGER.warning(
                "BinSkim executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_binskim_plugins\"]' --tool binskim`."
            )
        return found is not None


__all__ = [
    "BINSKIM_LEVEL_MAP",
    "BinskimScanner",
    "BinskimScannerConfig",
    "BinskimScannerConfigOptions",
    "tree_holds_a_binary",
]
