# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GovulncheckScanner: known-vulnerability reachability for Go modules.

What it runs
------------
``govulncheck`` (golang.org/x/vuln/cmd/govulncheck, BSD-3-Clause) reads each Go
module in the scanned tree, matches the modules it uses against the Go
vulnerability database, and says whether the vulnerable symbol is actually
reachable from the module's code. It is a native tool that ASH invokes as a
separate process and never imports.

Scan shape (own ``scan()``, not the template)
---------------------------------------------
govulncheck has no flag that writes its report to a file: the SARIF document is
the program's standard output. The template ``scan()`` reads a results file the
tool wrote, so this scanner overrides ``scan()`` as hadolint does, reads stdout,
validates it into a ``SarifReport`` and writes it to the results directory itself.
One run is made per Go module found in the tree (a directory holding a
``go.mod``), because govulncheck refuses to run outside a module.

Invocation (read from the tool's own flag definitions in golang/vuln,
``internal/scan/flags.go``)::

    govulncheck -format=sarif -scan=<symbol|package|module> [-test=true] -- ./...

run with the module directory as the working directory.

* ``-format=sarif`` selects the SARIF writer.
* ``-scan`` is the precision level, default ``symbol``. The tool rejects
  patterns when it is ``module``, so no pattern is passed then.
* ``-test`` includes test files. Off unless the option is set.
* ``--`` ends flag parsing before the ``./...`` pattern.
* ``-db`` is never passed: the tool's default is https://vuln.go.dev, and an
  option the scanned tree could set to point at another database would let a
  tree choose what counts as a vulnerability.
* ``-show`` is not valid with a non-text format and is never passed.

Exit status (govulncheck docs): with ``-format sarif`` the tool "exits
successfully" whatever it found, so the exit code says nothing about findings.
Only the report body does. Exit 0 is therefore the one accepted code, and any
other code fails the scan even if bytes arrived on stdout (a tool failure such as
a package that does not load, or a database that could not be fetched). Measured
with v1.9.0: the SARIF run that found fifteen vulnerabilities exited 0, and the
text run over the same module exited 3.

Captured output (v1.9.0, tests/test_data/scanners/govulncheck/captured)
-------------------------------------------------------------------------
Each result's one location is the module's ``go.mod`` at ``region.startLine`` 1,
with no column: the finding names the module, not a line. A symbol-level result
also carries ``codeFlows`` and ``stacks`` whose frames name the calling source
line and the vulnerable function; ASH keeps the ``go.mod`` location and does not
read the frames. Each rule carries the advisory summary (``shortDescription`` and
``fullDescription``), its details (``help``), a ``helpUri`` on pkg.go.dev, and the
advisory's CVE aliases as its ``properties.tags``. The driver writes
``semanticVersion`` (not ``version``) and properties naming the Go version, the
database's modification time and the scan level. No result carries a fingerprint,
a snippet or a fixed version.

Severity
--------
govulncheck writes one SARIF level per result: ``error`` when the vulnerable
symbol is called (its default ``symbol`` scan level), ``warning`` when only the
package is imported, and ``note`` when only the module is required. ASH rates
them HIGH, MEDIUM and LOW, and sets the SARIF level so both agree. They are not
CRITICAL: the report carries no CVSS score, and a called symbol is evidence of
reachability, not of exploitability. A result with no level is MEDIUM, and a
level of ``none`` is INFO, and any other level is HIGH, so an unknown value
is never under-reported.

The Go toolchain
----------------
govulncheck loads packages through the ``go`` command, which ASH does not
install. Without ``go`` on ``PATH``, v1.9.0 exits 1 and says "no go.mod file"
even inside a module (measured), so the scanner checks for ``go`` before it runs
and reports the missing program instead of a misleading tool failure.

Offline and sandbox
-------------------
The vulnerability database is fetched at scan time and Go may fetch modules, so
the scan needs a network (``SandboxRequirements(network=True)``) and is skipped
under ``--offline`` (``OfflineStrategy.SKIP_OFFLINE``).

Opt-in
------
Listing this module in ``ash_plugin_modules`` is the opt-in. There is no license
or service gate: the tool is BSD-3-Clause and the database is public and
unauthenticated.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import AnyUrl, Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import (
    CustomCommand,
    install_story_is_declared,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base import scanner_operational_facets as opsf
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
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.download_utils import (
    NO_BIN_DIRECTORY,
    current_bin_path,
    refusing_install_command,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The govulncheck release ``go install`` fetches. A Go module version, so it is
#: pinned here and not in ``utils/tool_downloads.py`` (which pins release assets);
#: ``go install`` checks the module it fetches against the Go checksum database.
GOVULNCHECK_VERSION = "v1.9.0"

#: The Go package that holds the command.
GOVULNCHECK_PACKAGE = "golang.org/x/vuln/cmd/govulncheck"

#: govulncheck SARIF level -> (ASH severity, SARIF level). See the module docstring.
GOVULNCHECK_LEVEL_MAP: Dict[str, Tuple[str, Level]] = {
    "error": ("HIGH", Level.error),
    "warning": ("MEDIUM", Level.warning),
    "note": ("LOW", Level.note),
    "none": ("INFO", Level.none),
}

#: Directories never searched for a ``go.mod``: they hold other people's modules.
_SKIPPED_DIRS = frozenset({".git", "node_modules", "vendor", "testdata"})

#: A tree with more modules than this fails the scan instead of being cut short,
#: so a partial scan is never reported as a complete one.
MAX_MODULES = 200

#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic

#: Why a host without the Go toolchain cannot run the scan (see the docstring).
GO_TOOLCHAIN_MISSING = (
    "Go not found on PATH: govulncheck loads packages through the Go toolchain "
    "(`go`), which ASH does not install, and without it govulncheck fails with "
    '"no go.mod file" even inside a module. Install Go and put `go` on PATH.'
)


class GovulncheckScannerConfigOptions(ScannerOptionsBase):
    scan_level: Annotated[
        Literal["symbol", "package", "module"],
        Field(
            description=(
                "govulncheck's -scan level. symbol reports a vulnerability as an "
                "error only when a vulnerable function is reachable from the "
                "module's code; package and module are less precise and report "
                "more."
            ),
        ),
    ] = "symbol"
    include_tests: Annotated[
        bool,
        Field(
            description=(
                "Also analyze _test.go files (govulncheck -test). Off by default: "
                "test-only code does not ship."
            ),
        ),
    ] = False


class GovulncheckScannerConfig(ScannerPluginConfigBase):
    name: Literal["govulncheck"] = "govulncheck"
    enabled: bool = True
    options: Annotated[
        GovulncheckScannerConfigOptions,
        Field(description="Configure the govulncheck scanner"),
    ] = GovulncheckScannerConfigOptions()


def _level_name(level: Any) -> Optional[str]:
    """A SARIF level's string value, whether it holds the enum or the string."""
    if level is None:
        return None
    return str(getattr(level, "value", level)).lower()


@ash_scanner_plugin
class GovulncheckScanner(ScannerPluginBase[GovulncheckScannerConfig]):
    """Go vulnerability reachability analysis using govulncheck."""

    #: A native Go binary, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    #: Programs govulncheck needs that ASH does not install: it runs the Go
    #: toolchain to load packages. ``ash dependencies install`` reads this to say
    #: whether the scanner can run after its install.
    external_executables: ClassVar[tuple[str, ...]] = ("go",)

    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name govulncheck's own SARIF; the corpus is the captured v1.9.0 run in
    #: tests/test_data/scanners/govulncheck/captured/, read through
    #: apply_severity_mapping, the adapter's one step over a root module's report.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (the Go vulnerability database id, '
            "GO-yyyy-nnnn)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (error, warning, note) through '
            "GOVULNCHECK_LEVEL_MAP onto issue_severity and the SARIF level",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[0].physicalLocation.artifactLocation.uri, the "
            "module's go.mod; the adapter prefixes the module directory for a "
            "module below the scanned root",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startLine of the go.mod location (1 in every "
            "captured result: the finding names the module, not a line)",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the go.mod location carries a start line only; the columns "
            "govulncheck writes sit on the codeFlows and stacks frames, which the "
            "adapter does not read",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text" (the packages the code calls or '
            "imports the vulnerability in)",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="a vulnerable Go module is a package locator, not a deployable "
            "resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="a vulnerable Go module is a package, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.DROPPED,
            native_field='the package named in "message.text", and the "module" of '
            "each codeFlows and stacks frame (stdlib@v1.27.0 in the capture)",
            reason="the adapter writes no package property, so the package is "
            "carried in the message text only",
        ),
        package_version=FacetDecl(
            state=FacetState.DROPPED,
            native_field='the version after "@" in a frame\'s "module" '
            "(symbol-level results only)",
            reason="the adapter does not read the frames, so no package version "
            "is written",
        ),
        package_path=FacetDecl(
            state=FacetState.DROPPED,
            native_field="the go.mod location that requires the module",
            reason="the go.mod is written as the finding's file, not as a package "
            "path property",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rules[] properties "tags" (the advisory\'s CVE aliases)',
            reason="the flat CVE is read from the rule id, which is the GO id; the "
            "adapter does not carry the alias",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries no CWE: the rule tags hold the advisory's CVE "
            "aliases only",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="govulncheck's SARIF writes no fingerprints or partialFingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries no fixed version; the text format's "
            '"Fixed in" line has no SARIF counterpart',
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the rules carry the advisory's summary and details "
            "(fullDescription, help), not a fix instruction",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the go.mod location carries no region snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rules[] "helpUri" (the advisory page on pkg.go.dev)',
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="the vulnerability and security tags the adapter writes on "
            "every result; the rule tags (the CVE aliases) are not carried",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="govulncheck",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.VULN_DB, opsf.Fetched.MODULE_SOURCES),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason="the Go vulnerability database is read from "
                "vuln.go.dev at scan time and nothing is bundled",
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source="govulncheck_scanner.py module header (Offline and sandbox), "
                "offline_strategy, sandbox_requirements",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="SARIF is read from stdout; the tool has no report-file flag",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection="one run per directory holding a go.mod "
                "(GovulncheckScanner._modules)",
                covers_note=(
                    "the alpha scanners declare no covers display string; go.mod "
                    "is the Go dependency manifest, which govulncheck reads with "
                    "the code that imports it"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("go",),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one govulncheck run per Go module",
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for govulncheck.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="ASH downloads no binary; the install command runs `go install` "
                "of the pinned module version and needs a Go toolchain on linux or "
                "darwin",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the tool's SARIF level (error/warning/note) maps to "
                "HIGH/MEDIUM/LOW",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="govulncheck has no ignore file or inline suppression "
                "that ASH passes or reads; ASH's own suppressions apply",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="no fingerprint (captured v1.9.0 run); identity is the go.mod "
                "location, its line 1 and the GO id",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("GO",),
                options_surface="options.scan_level and options.include_tests; the "
                "database URL (-db) is never passed",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="with -format sarif the tool exits 0 whatever it finds, so "
                "any other code is a tool failure",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_govulncheck_plugins in ash_plugin_modules",
                    "options.scan_level",
                    "options.include_tests",
                ),
                upstream_license="BSD-3-Clause (source: the LICENSE file of the "
                "golang.org/x/vuln v1.9.0 module, read 2026-11-26; byte-identical "
                "to the LICENSE at the v1.9.0 tag commit e672cbe8; no license or "
                "service gate, the module is built by `go install` and never "
                "vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="a go.mod in the scanned tree; a tree with none is skipped",
            ),
        )
    )

    # The database is read from vuln.go.dev at scan time; nothing is bundled.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    # With -format sarif the tool exits 0 whatever it finds; any other code is a failure.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The database fetch and Go's module resolution need a network. GOMODCACHE and
    # GOCACHE are read-only caches the Go command fills outside the sandbox; the
    # GO* variables (GOPROXY, GOFLAGS...) are the operator's own.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=(
            "~/go/pkg/mod",
            "$GOMODCACHE",
            "~/.cache/go-build",
            "$GOCACHE",
        ),
        cache_env=("GOCACHE",),
        env_prefixes=("GO",),
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = GovulncheckScannerConfig()
        self.command = "govulncheck"
        self.tool_type = ScannerToolType.SCA
        # The argv is assembled in _argv; nothing from the base resolver is added.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "GovulncheckScanner":
        """``go install`` of the pinned module version into ASH's bin directory.

        Needs a Go toolchain, which ASH does not install. Without one the scanner
        declares no command and is reported as having no install path here, so
        ``ash dependencies install`` does not fail for every other plugin.
        Windows is not declared: the command sets GOBIN through the shell.
        """
        declaring = install_story_is_declared()
        if not declaring and find_executable("go") is None:
            return self
        bin_dir = current_bin_path()
        if declaring and bin_dir is None:
            bin_dir = Path("ASH_BIN_PATH")
        command = (
            refusing_install_command(NO_BIN_DIRECTORY)
            if bin_dir is None
            else CustomCommand(
                args=[
                    f"GOBIN={shlex.quote(str(bin_dir))}",
                    "go",
                    "install",
                    f"{GOVULNCHECK_PACKAGE}@{GOVULNCHECK_VERSION}",
                ],
                shell=True,
            )
        )
        for target_platform in ("linux", "darwin"):
            for arch in ("amd64", "arm64"):
                self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                    command
                ]
        return self

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: govulncheck overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("GovulncheckScanner has no plugin context")
        return self.context

    def _options(self) -> GovulncheckScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, GovulncheckScannerConfigOptions):
            return options
        return GovulncheckScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _argv(self) -> List[str]:
        """The govulncheck argv for one module; the module is the working directory.

        Every option is one ``-flag=value`` token. With ``-scan=module`` the tool
        refuses patterns, so none is given; otherwise ``./...`` follows ``--``.
        """
        options = self._options()
        argv = [
            self.command or "govulncheck",
            "-format=sarif",
            f"-scan={options.scan_level}",
        ]
        if options.include_tests:
            argv.append("-test=true")
        if options.scan_level != "module":
            argv.extend(["--", "./..."])
        return argv

    def _modules(
        self, target: Path, global_ignore_paths: List[IgnorePathWithReason]
    ) -> List[Path]:
        """Directories under *target* that hold a go.mod, sorted, links not followed."""
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        root = Path(target).absolute()
        found: List[Path] = []
        for current, dirs, files in os.walk(root, followlinks=False):
            here = Path(current)
            dirs[:] = sorted(
                d
                for d in dirs
                if d not in _SKIPPED_DIRS and not (here / d).is_symlink()
            )
            if "go.mod" not in files or (here / "go.mod").is_symlink():
                continue
            relative = here.relative_to(root).as_posix()
            if any(
                file_path_matches(
                    f"{relative}/go.mod" if relative != "." else "go.mod", i.path
                )
                for i in global_ignore_paths
            ):
                continue
            found.append(here)
        return sorted(found)

    @staticmethod
    def _empty_report(version: Optional[str] = None) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="govulncheck",
                            version=version,
                            informationUri=AnyUrl(
                                "https://pkg.go.dev/golang.org/x/vuln"
                            ),
                        )
                    ),
                    results=[],
                )
            ],
        )

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: GovulncheckScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Run govulncheck once per Go module under *target* and merge the reports."""
        if global_ignore_paths is None:
            global_ignore_paths = []
        self.targets_attempted = 0
        self.targets_failed = 0

        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file: Optional[Path] = None
        try:
            if self._scanner_offline():
                self._plugin_log(
                    "govulncheck fetches the Go vulnerability database at scan time, "
                    "so it is skipped in offline mode.",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            modules = self._modules(target, global_ignore_paths)
            if not modules:
                self._plugin_log(
                    f"No go.mod found in {target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()
            if len(modules) > MAX_MODULES:
                raise ScannerError(
                    f"the tree holds {len(modules)} Go modules, more than the "
                    f"{MAX_MODULES} one scan covers; narrow it with ignore_paths "
                    "rather than get a partial result"
                )

            self.targets_attempted = len(modules)
            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("govulncheck.sarif")
            results_file.unlink(missing_ok=True)

            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout
            argv = self._argv()
            root = Path(target).absolute()

            merged: Optional[SarifReport] = None
            for module in modules:
                remaining = None if deadline is None else deadline - _now()
                if remaining is not None and remaining <= 0:
                    raise ScannerError(
                        f"govulncheck ran out of its {timeout}s budget before "
                        f"scanning {module.relative_to(root).as_posix() or '.'}; "
                        "raise scanners.govulncheck.options.scan_timeout"
                    )
                response = self._run_subprocess(
                    command=argv,
                    results_dir=results_dir,
                    cwd=module,
                    stdout_preference="return",
                    stderr_preference="both",
                    timeout=remaining,
                )
                response = response if isinstance(response, dict) else {}
                self._refuse_flagged_response(response, timeout)
                if self.exit_code not in self.success_exit_codes:
                    stderr = (response.get("stderr") or "").strip()
                    raise ScannerError(
                        f"govulncheck exited {self.exit_code} in "
                        f"{module.relative_to(root).as_posix() or '.'}; with "
                        "-format sarif it exits 0 even when it finds "
                        "vulnerabilities, so this run failed"
                        + (f": {tool_output_excerpt(stderr, 500)}" if stderr else "")
                    )
                report = self._parse_sarif(response)
                self._prefix_locations(report, module, root)
                if merged is None:
                    merged = report
                else:
                    self._merge(merged, report)
            self._post_scan(target=target, target_type=target_type)

            if merged is None:  # pragma: no cover - modules is non-empty here
                raise ScannerError("govulncheck produced no report")
            driver = merged.runs[0].tool.driver
            # govulncheck's SARIF writer sets ``semanticVersion``; ``version``
            # is the fallback for a writer that uses the other field.
            detected_version = driver.semanticVersion or driver.version
            if detected_version:
                self.tool_version = detected_version
            self.apply_severity_mapping(merged)
            with open_for_write(results_file) as handle:
                handle.write(
                    merged.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            self._inject_invocation(merged, argv, target)
            return merged
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

    @staticmethod
    def _parse_sarif(response: Dict[str, Any]) -> SarifReport:
        """The SARIF govulncheck wrote to stdout, validated; raises when it is not."""
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            raise ScannerError("govulncheck exited 0 but wrote no report")
        try:
            document = json.loads(stdout)
        except ValueError as e:
            raise ScannerError(f"govulncheck's output is not JSON: {e}")
        if not isinstance(document, dict):
            raise ScannerError("govulncheck's output is not a SARIF document")
        try:
            report = SarifReport.model_validate(document)
        except ValueError as e:
            raise ScannerError(f"govulncheck's output is not valid SARIF: {e}")
        if not report.runs:
            raise ScannerError("govulncheck wrote a SARIF report with no runs")
        return report

    @staticmethod
    def _prefix_locations(report: SarifReport, module: Path, root: Path) -> None:
        """Make each result's go.mod URI relative to the scanned tree.

        govulncheck names the go.mod of the module it ran in, as ``go.mod``. For a
        module below the tree root the URI gets the module's directory in front.
        """
        relative = PurePosixPath(module.relative_to(root).as_posix())
        if str(relative) in ("", "."):
            return
        for result in report.get_all_results():
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                if artifact is not None and artifact.uri:
                    artifact.uri = (relative / artifact.uri).as_posix()

    @staticmethod
    def _merge(into: SarifReport, other: SarifReport) -> None:
        """Add *other*'s results and rules to *into*'s first run."""
        run, extra = into.runs[0], other.runs[0]
        run.results = [*(run.results or []), *(extra.results or [])]
        known = {r.id for r in (run.tool.driver.rules or [])}
        added = [r for r in (extra.tool.driver.rules or []) if r.id not in known]
        if added:
            run.tool.driver.rules = [*(run.tool.driver.rules or []), *added]

    @staticmethod
    def apply_severity_mapping(sarif_report: SarifReport) -> SarifReport:
        """Rewrite each result's ASH severity and SARIF level from its level."""
        for result in sarif_report.get_all_results():
            # No level arrives as the SARIF model's default (warning) -> MEDIUM.
            # None or a name the table lacks is read as error -> HIGH.
            name = _level_name(result.level) or "error"
            severity, level = GOVULNCHECK_LEVEL_MAP.get(
                name, GOVULNCHECK_LEVEL_MAP["error"]
            )
            result.level = level
            if result.properties is None:
                result.properties = PropertyBag()
            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("vulnerability", "security"):
                if tag not in tags:
                    tags.append(tag)
            result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "govulncheck")
        if not found:
            ASH_LOGGER.warning(
                "govulncheck executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_govulncheck_plugins\"]' --tool govulncheck`."
            )
            return False
        reason = self._forced_binary_precluded_reason()
        if reason:
            # Recorded, not only returned: a bare False would leave the scanner
            # MISSING with no reason anywhere in the results.
            ASH_LOGGER.warning(reason)
            self.dependency_unavailable_reason = reason
            self.dependencies_satisfied = False
            return False
        return True

    def _forced_binary_precluded_reason(self) -> Optional[str]:
        """A forced govulncheck binary still needs the Go toolchain to run.

        The gate of ``validate_plugin_dependencies`` mirrored, as the base asks of
        a scanner whose check answers more than where its binary is: without it a
        ``--binary-path`` record would satisfy the check on a host with no ``go``.
        """
        if any(not find_executable(name) for name in self.external_executables):
            return GO_TOOLCHAIN_MISSING
        return None


__all__ = [
    "GOVULNCHECK_LEVEL_MAP",
    "GOVULNCHECK_VERSION",
    "GO_TOOLCHAIN_MISSING",
    "GovulncheckScanner",
    "GovulncheckScannerConfig",
    "GovulncheckScannerConfigOptions",
]
