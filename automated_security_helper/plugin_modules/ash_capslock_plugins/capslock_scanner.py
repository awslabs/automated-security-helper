# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CapslockScanner: Go dependency capabilities with Google's Capslock.

What it runs
------------
``capslock`` (https://github.com/google/capslock, BSD-3-Clause) reports which
privileged operations (files, network, exec, unsafe, cgo, ...) a Go package can
reach through its transitive calls. This plugin runs it once per Go module found
in the target and turns each reported capability into one SARIF result.

Scan flow
---------
Capslock prints its JSON report on stdout and writes no report file, so the
template ``scan()`` (which reads a results file) does not fit. This scanner
overrides ``scan()`` the way the hadolint plugin does and reads stdout.

Invocation (read from the tool's source, cmd/capslock/capslock.go)
------------------------------------------------------------------
``capslock -packages=./... -output=json -force_local_module``, run in the
directory of each ``go.mod``:

- ``-output=json`` selects the JSON mode (the tool's ``json`` / ``j`` mode,
  printed by protojson, so field names are lowerCamelCase and 64-bit integers
  are strings).
- ``-force_local_module`` stops Capslock from falling back, when the packages
  cannot be loaded, to creating a temporary module and running ``go get`` for
  them. That fallback reaches the network and analyzes something other than the
  scanned tree; with the flag the tool returns an error instead.
- ``-packages=./...`` is the tool's own spelling of "this module".
- ``GOFLAGS=-mod=readonly`` is set in the tool's environment so a ``GOFLAGS``
  inherited from a shell cannot make ``go`` rewrite ``go.mod``.

Capslock has no flag that reads a configuration file from the scanned tree, and
this plugin passes none (no ``-capability_map``), so nothing in the tree can
change what is reported. There are no operator-only options.

Targets
-------
Only directories that hold a ``go.mod`` are analyzed. A tree with none has
nothing to analyze: the scan is SKIPPED (no target attempted), not passed.
``vendor``, ``node_modules``, ``.git`` and ``testdata`` directories are not
searched for modules. A module whose ``go.mod`` or directory an operator ignore
path covers (``global_ignore_paths``) is not analyzed.

Severity
--------
Every capability is INFO, SARIF level ``none``, kind ``informational``. A
capability is an inventory of what the code *can* do, not a vulnerability: a
web server reaching NETWORK is expected. The plugin is a review aid, so it does
not fail a scan on its own. ``issue_severity`` and the SARIF level agree on every
result (``tests`` pin this).

Exit status and output
----------------------
Per the tool's source: exit 0 on success, 1 only for a ``compare`` difference
(never requested here) and 2 for any error. Only 0 is accepted; anything else
fails the scan, even with output on stdout. Empty or non-JSON stdout fails the
scan.

Offline
-------
The analysis is local. Loading the Go packages needs their modules in the module
cache or a ``vendor`` directory; the strict sandbox has no network, so a module
that is not cached makes Capslock exit 2 and the scan fails with that status.

Install
-------
Capslock publishes no releases; it is installed with
``go install github.com/google/capslock/cmd/capslock@latest`` by the user. ASH
does not install it. A missing binary skips the scanner with that command in the
log.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set

from pydantic import AnyUrl, Field

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
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
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.suppression_matcher import ignore_path_matches

#: Directories never searched for a ``go.mod``.
_SKIPPED_DIRS = frozenset({"vendor", "node_modules", ".git", "testdata"})

#: Most modules analyzed in one scan; a larger monorepo fails loudly rather than
#: silently dropping modules.
MAX_MODULES = 200

#: The install command a user runs; Capslock has no release assets.
INSTALL_COMMAND = "go install github.com/google/capslock/cmd/capslock@latest"

#: Capability name (``CAPABILITY_`` prefix removed) -> one-line meaning, from
#: the tool's docs/capabilities.md.
CAPABILITY_DESCRIPTIONS: Dict[str, str] = {
    "FILES": "read or modify the file system",
    "NETWORK": "interact with the network",
    "RUNTIME": "read or modify sensitive information from the Go runtime",
    "READ_SYSTEM_STATE": "read information about the system state and environment",
    "MODIFY_SYSTEM_STATE": "modify the state of the system or environment",
    "OPERATING_SYSTEM": "perform uncategorized operations in the os package",
    "SYSTEM_CALLS": "make direct system calls",
    "ARBITRARY_EXECUTION": "invoke assembler code or violate Go's type safety",
    "CGO": "execute native code through cgo",
    "UNANALYZED": "reach a call path Capslock could not analyze",
    "UNSAFE_POINTER": "use unsafe.Pointer",
    "REFLECT": "use reflection",
    "EXEC": "execute other programs",
}

#: ASH severity for every capability; see "Severity" in the module docstring.
CAPSLOCK_SEVERITY = "INFO"
#: SARIF level that agrees with ``CAPSLOCK_SEVERITY``.
CAPSLOCK_LEVEL = "none"


def capability_name(raw: Any) -> str:
    """``CAPABILITY_FILES`` or ``FILES`` -> ``FILES``; empty for anything else."""
    if not isinstance(raw, str):
        return ""
    name = raw.strip().upper()
    name = name.removeprefix("CAPABILITY_")
    return name


def find_go_modules(target: Path) -> List[Path]:
    """Directories under *target* holding a ``go.mod``, sorted, links not followed."""
    modules: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIPPED_DIRS)
        if "go.mod" in filenames and not os.path.islink(
            os.path.join(dirpath, "go.mod")
        ):
            modules.append(Path(dirpath))
    return modules


def drop_ignored_modules(
    modules: List[Path],
    target: Path,
    global_ignore_paths: List[IgnorePathWithReason] | None,
) -> List[Path]:
    """*modules* without those an operator ignore path covers.

    A module is ignored when its ``go.mod`` or its directory matches an ignore
    path, matched as every ASH ignore path is (``ignore_path_matches``: one ending
    in ``/`` names a directory and everything below it). Capslock is handed one
    module at a time, so a whole module under an ignored path is never analyzed,
    rather than analyzed and dropped afterwards.
    """
    if not global_ignore_paths:
        return list(modules)
    kept: List[Path] = []
    for module_dir in modules:
        try:
            relative = PurePosixPath(module_dir.relative_to(target))
        except ValueError:
            kept.append(module_dir)
            continue
        go_mod = (relative / "go.mod").as_posix()
        directory = relative.as_posix()
        candidates = [go_mod] if directory in ("", ".") else [go_mod, directory]
        if any(
            ignore_path_matches(candidate, ignore.path)
            for ignore in global_ignore_paths
            for candidate in candidates
        ):
            ASH_LOGGER.verbose(f"capslock: skipping ignored module {go_mod}")
            continue
        kept.append(module_dir)
    return kept


def _int(value: Any) -> Optional[int]:
    """protojson writes int64 as a string; accept both."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _relative_uri(filename: Any, module_dir: Path, target: Path) -> Optional[str]:
    """A source-relative POSIX URI for *filename*, or None when outside *target*."""
    if not isinstance(filename, str) or not filename:
        return None
    path = Path(filename)
    if not path.is_absolute():
        path = module_dir / path
    path = Path(os.path.normpath(path))
    try:
        return PurePosixPath(path.relative_to(os.path.normpath(target))).as_posix()
    except ValueError:
        return None


def convert_capslock_output(
    document: Any, module_dir: Path, target: Path
) -> List[Dict[str, Any]]:
    """SARIF result dicts for one module's ``capslock -output=json`` document.

    Raises ``ValueError`` when *document* is not a Capslock report object.
    """
    if not isinstance(document, dict):
        raise ValueError("the report is not a JSON object")
    infos = document.get("capabilityInfo", [])
    if infos is None:
        infos = []
    if not isinstance(infos, list):
        raise ValueError("capabilityInfo is not a list")

    go_mod_uri = _relative_uri("go.mod", module_dir, target) or "go.mod"
    results: List[Dict[str, Any]] = []
    for info in infos:
        if not isinstance(info, dict):
            raise ValueError("a capabilityInfo entry is not an object")
        name = capability_name(info.get("capabilityName") or info.get("capability"))
        if not name:
            raise ValueError("a capabilityInfo entry names no capability")
        package = str(info.get("packageName") or "")
        kind = capability_name(info.get("capabilityType")).replace("TYPE_", "")
        path = info.get("path") if isinstance(info.get("path"), list) else []

        uri, line, column = None, None, None
        for step in path:
            site = step.get("site") if isinstance(step, dict) else None
            if isinstance(site, dict):
                uri = _relative_uri(site.get("filename"), module_dir, target)
                if uri:
                    line, column = _int(site.get("line")), _int(site.get("column"))
                    break
        if uri is None:
            uri = go_mod_uri

        chain = str(info.get("depPath") or "").strip()
        meaning = CAPABILITY_DESCRIPTIONS.get(name, name.lower())
        text = f"Package {package or '(unknown)'} can {meaning} ({name}"
        text += f", {kind.lower()})." if kind else ")."
        if chain:
            text += f" Example call path: {chain}"

        region: Dict[str, Any] = {}
        if line:
            region["startLine"] = line
            if column:
                region["startColumn"] = column
        physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if region:
            physical["region"] = region
        results.append(
            {
                "ruleId": f"CAPSLOCK-{name}",
                "level": CAPSLOCK_LEVEL,
                "kind": "informational",
                "message": {"text": text},
                "locations": [{"physicalLocation": physical}],
                "properties": {
                    "issue_severity": CAPSLOCK_SEVERITY,
                    "capslock_capability": name,
                    "capslock_package": package,
                    "capslock_type": kind,
                    "tags": ["capability", "go"],
                },
            }
        )
    return results


class CapslockScannerConfigOptions(ScannerOptionsBase):
    """Capslock has no options of its own; the base options (timeout, ...) apply."""


class CapslockScannerConfig(ScannerPluginConfigBase):
    name: Literal["capslock"] = "capslock"
    enabled: bool = True
    options: Annotated[
        CapslockScannerConfigOptions, Field(description="Configure Capslock")
    ] = CapslockScannerConfigOptions()


@ash_scanner_plugin
class CapslockScanner(ScannerPluginBase[CapslockScannerConfig]):
    """Reports the capabilities Go code can reach, with Capslock."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # Python is not required to run it: a native Go binary.
    python_only: ClassVar[bool | None] = False
    # 0 is the only status of a completed run; 2 is any error (see docstring).
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default: no network, baseline environment only. Module download
    # for uncached dependencies is therefore unavailable; see "Offline".
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: native fields name Capslock's ``-output=json`` document (the protobuf in
    #: its proto/capability.proto, rendered by protojson), which this adapter
    #: converts to SARIF. No Capslock binary has been run for this plugin (the
    #: build host has no Go toolchain), so the cells rest on the schema and the
    #: schema-derived fixtures in tests/test_data/scanners/capslock/schema_derived.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="capabilityInfo[].capabilityName (e.g. CAPABILITY_NETWORK), "
            "written as the ruleId CAPSLOCK-<NAME>",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native severity) the adapter writes INFO for every "
            "capability, SARIF level none",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="capabilityInfo[].path[].site.filename of the first call "
            "site inside the target; go.mod when none is",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="capabilityInfo[].path[].site.line",
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field="capabilityInfo[].path[].site.column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="capabilityInfo[] packageName, capabilityName, "
            "capabilityType and depPath, assembled into one sentence by the adapter",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="a finding is a Go package's reachable capability at a call "
            "site, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="a finding is a Go package's reachable capability at a call "
            "site, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.DROPPED,
            native_field="capabilityInfo[].packageName",
            reason="kept only in the result property capslock_package, which the "
            "flat row does not read as a package name; it is the package that "
            "reaches the capability, not a dependency to upgrade",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="Capslock reports packages by import path with no version",
        ),
        package_path=FacetDecl(
            state=FacetState.DROPPED,
            native_field="capabilityInfo[].packageDir",
            reason="the adapter does not write it; the call site is the location",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="a capability inventory carries no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="a capability inventory carries no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="Capslock output carries no finding fingerprint and the "
            "adapter computes none; identity is file and line through the "
            "shared floor",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="a capability is an inventory entry, not a defect with a fix",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="Capslock results carry no remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the report carries call-site positions and a call path, not "
            "source text",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="Capslock results carry no reference links",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result property "tags" (capability, go), written by '
            "the adapter",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "capslock_capability", '
            '"capslock_package" and "capslock_type" (capabilityType)',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="capslock",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "capslock_scanner.py offline_strategy, sandbox_requirements and "
                    "the module header: -force_local_module stops the module-download "
                    "fallback and GOFLAGS=-mod=readonly stops go rewriting go.mod; a "
                    "module missing from the cache fails the scan"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="-output=json on stdout; the adapter reads stdout, no report file",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection="every directory holding a go.mod (find_go_modules), "
                "minus vendor, node_modules, .git, testdata and operator ignore paths",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("capslock", "go"),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one capslock run per go.mod directory",
                python_only=False,
                use_uv_tool=False,
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="Capslock publishes no release assets; the user installs it "
                "with go install, so ASH provisions nothing",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.CONSTANT,
                note="INFO for every capability (SARIF level none, kind "
                "informational): a capability is an inventory, not a defect",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="no tool-side silencing surface was surveyed and the "
                "adapter passes no configuration flag; ASH suppressions and "
                "ignore paths are the surface this register records",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="no native or computed fingerprint; identity is the "
                "ruleId, file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="the base options only; -capability_map is never "
                "passed, so nothing in the tree changes what is reported",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="from cmd/capslock/capslock.go: 0 success, 1 only for a "
                "compare difference (never requested), 2 any error",
            ),
            provenance=opsf.ProvenanceFacet(
                tier=opsf.Tier.COMMUNITY_OPTIN,
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_capslock_plugins in ash_plugin_modules",),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.MANIFEST,),
                note="a go.mod per module, with its dependencies in the module "
                "cache or a vendor directory",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CapslockScannerConfig()
        self.command = "capslock"
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: Capslock overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("CapslockScanner has no plugin context")
        return self.context

    @staticmethod
    def _subprocess_env() -> Dict[str, str]:
        env = dict(snapshot_environ())
        env["GOFLAGS"] = "-mod=readonly"
        return env

    def _argv(self) -> List[str]:
        return [
            self.command or "capslock",
            "-packages=./...",
            "-output=json",
            "-force_local_module",
        ]

    def _empty_report(self) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="Capslock",
                            version=self.tool_version,
                            informationUri=AnyUrl("https://github.com/google/capslock"),
                        )
                    ),
                    results=[],
                )
            ],
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CapslockScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Run Capslock in every Go module under *target* and merge the results."""
        self.targets_attempted = 0
        self.targets_failed = 0
        self.exit_code = 0
        self.start_time = None
        self.end_time = None
        self.output = []
        self._reset_errors()

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

        try:
            found = find_go_modules(target)
            modules = drop_ignored_modules(found, target, global_ignore_paths)
            if not modules:
                reason = (
                    "every Go module found is under an ignored path"
                    if found
                    else "No go.mod found"
                )
                self._plugin_log(
                    f"{reason} in {target_type} directory; nothing for "
                    "Capslock to analyze.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()
            if len(modules) > MAX_MODULES:
                raise ScannerError(
                    f"{len(modules)} Go modules found; Capslock analyzes at most "
                    f"{MAX_MODULES} per scan"
                )

            self.targets_attempted = len(modules)
            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)

            timeout = self._effective_scan_timeout()
            argv = self._argv()
            report = self._empty_report()
            merged: List[Dict[str, Any]] = []
            for module_dir in modules:
                response = self._run_subprocess(
                    command=argv,
                    results_dir=results_dir,
                    cwd=module_dir,
                    stdout_preference="return",
                    stderr_preference="both",
                    env=self._subprocess_env(),
                    timeout=timeout,
                )
                response = response if isinstance(response, dict) else {}
                if response.get("timed_out"):
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        f"capslock timed out after {timeout}s and was killed, so it "
                        "produced no report. Raise "
                        "scanners.capslock.options.scan_timeout if this module "
                        "legitimately needs longer."
                    )
                if self.exit_code not in self.success_exit_codes:
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        f"capslock exited {self.exit_code} in "
                        f"{self._module_label(module_dir, target)}. It exits 2 for "
                        "any error, for example Go packages that cannot be loaded "
                        "because a module is not in the module cache. It said: "
                        + tool_output_excerpt(
                            (response.get("stderr") or "").strip(), 500
                        )
                    )
                try:
                    document = self._parse_stdout(response)
                    merged.extend(convert_capslock_output(document, module_dir, target))
                except ValueError as bad:
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        f"capslock output for {self._module_label(module_dir, target)}"
                        f" could not be read: {bad}"
                    ) from bad
            self._post_scan(target=target, target_type=target_type)

            report = SarifReport.model_validate(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": "Capslock",
                                    "informationUri": "https://github.com/google/capslock",
                                }
                            },
                            "results": merged,
                        }
                    ],
                }
            )
            self._inject_invocation(report, argv, target)
            return report
        except ScannerError:
            raise
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, None)) from e

    @staticmethod
    def _module_label(module_dir: Path, target: Path) -> str:
        try:
            rel = PurePosixPath(module_dir.relative_to(target)).as_posix()
        except ValueError:
            rel = module_dir.as_posix()
        return "the target root module" if rel in ("", ".") else f"module {rel}"

    @staticmethod
    def _parse_stdout(response: Dict[str, Any]) -> Any:
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            raise ValueError("it exited 0 but wrote no report")
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as bad:
            raise ValueError("stdout is not JSON") from bad

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "capslock")
        if not found:
            ASH_LOGGER.warning(
                "capslock executable not found in PATH. ASH does not install it "
                f"(Capslock publishes no releases); run `{INSTALL_COMMAND}` and "
                "make sure the Go bin directory is on PATH."
            )
        return found is not None


__all__ = [
    "CAPABILITY_DESCRIPTIONS",
    "CAPSLOCK_LEVEL",
    "CAPSLOCK_SEVERITY",
    "CapslockScanner",
    "CapslockScannerConfig",
    "CapslockScannerConfigOptions",
    "capability_name",
    "convert_capslock_output",
    "find_go_modules",
]
