# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Kubernetes manifest linting over the scan target using KubeLinter (``kube-linter``).

KubeLinter checks Kubernetes YAML, Helm charts and Kustomize directories against a set
of built-in checks (``privileged-container``, ``run-as-non-root``, ``no-read-only-root-fs``
and so on). This plugin is the alpha scanner ``kube-linter``: a scan that does not list
``automated_security_helper.plugin_modules.ash_kube_linter_plugins`` in
``ash_plugin_modules`` is unchanged.

What was read, and from where (KubeLinter v0.8.3, the pinned release; source at the tag
``v0.8.3`` of github.com/stackrox/kube-linter, Apache-2.0):

Invocation
    ``kube-linter lint --format=sarif --output=<report> --config=<stub> -- <path>``.
    ``lint`` takes a file or a directory; Helm charts (a directory with ``Chart.yaml``)
    and Kustomize directories are detected and rendered by KubeLinter itself.
    ``--format`` is repeatable and paired by position with ``--output``; ASH passes one of
    each, so the SARIF goes to a file and nothing is read from stdout.
    (pkg/command/lint/command.go, format_output.go)

Configuration
    ASH always passes ``--config`` with a stub holding ``{}``, so the checks run are
    KubeLinter's defaults. Without ``--config``, KubeLinter reads ``.kube-linter.yaml``
    or ``.kube-linter.yml`` from its working directory (pkg/config/config.go:42 and
    :55-62), and ASH runs it from the source directory, so the stub is what keeps a
    config the scanned repository holds from switching checks off
    (``checks.exclude``, ``checks.doNotAutoAddDefaults``) or skipping paths
    (``checks.ignorePaths``).

Ignore annotations
    KubeLinter skips one check on an object annotated
    ``ignore-check.kube-linter.io/<check>``, and every check on an object annotated
    ``kube-linter.io/ignore-all``. Only the annotation key is compared; its value is
    never read (pkg/ignore/ignore.go:9-27). The comparison runs for every object and
    check with no config or flag condition (pkg/run/run.go:54-62), and no flag turns
    it off: none of ``lint``'s own flags (pkg/command/lint/command.go:207-216), the
    config flags it adds at :219 (pkg/config/flags.go:13-34) or the root command's
    one persistent flag (``--with-color``, pkg/command/root/command.go:38) touches
    annotations. So the scanned repository can drop findings this way and ASH cannot
    stop it: such a finding never reaches the report, so it is neither reported nor
    counted as suppressed.

Exit status
    ``lint`` returns an error, which the ``kube-linter`` program turns into exit 1, in
    two different cases: it found problems (``found N lint errors``), or it failed (a
    bad config, an unreadable path, a format that could not be written). Exit 0 means
    nothing was found, or no valid object was found and ``--fail-if-no-objects-found``
    was off (a warning goes to stderr and ``lint`` returns nil). ASH cannot tell the two
    exit-1 cases apart from the code. It tells them apart from the report: the report is
    deleted before each run, so exit 1 with a report on disk is "found problems" and
    exit 1 without one is a failed scan. Any code other than 0 and 1 fails the scan.
    Exit 0 with no report is read as "no Kubernetes object was found", and reported as
    a clean run with no results; the log says so.

Severity
    KubeLinter's SARIF carries no ``level`` on a result and no severity of its own: the
    check name is the ``ruleId``. ASH rates by the check. The checks in
    ``HIGH_SEVERITY_CHECKS`` are the ones whose finding is a setting that widens what
    a compromised container or role can reach (privileged containers, host namespaces,
    the Docker socket, privilege escalation, wildcard or cluster-admin RBAC). Every
    other check is MEDIUM: a workload hygiene gap (probes, limits, a read-only root
    file system, a pinned image tag). Nothing is CRITICAL: these are configuration
    findings, not a vulnerability in a running service. ``issue_severity`` and the SARIF
    level agree: HIGH is ``error``, MEDIUM is ``warning``.

    Five HIGH entries (``access-to-create-pods``, ``access-to-secrets``,
    ``cluster-admin-role-binding``, ``privileged-ports``, ``wildcard-in-rules``) are not
    among the 31 checks v0.8.3 enables by default, and ASH's empty stub config adds none,
    so they never fire in an ASH scan (a run over a cluster-admin binding and a wildcard
    ClusterRole with the stub config printed "No lint errors found!"; the same files with
    ``--do-not-auto-add-defaults --include=...`` reported both). They stay in the table so
    that a future change to the stub config rates them correctly. Turning those checks on
    changes what a scan reports, so it is not done here.

Locations
    KubeLinter writes every result at line 1 of the manifest (its source says this is
    to satisfy GitHub's code-scanning rules; real positions are a TODO upstream). ASH
    keeps the line as written and does not claim a better one.

Offline
    The checks are compiled into the binary and nothing is fetched at scan time for a
    plain manifest. Helm chart dependencies are not fetched by ASH; whether KubeLinter
    does so for a chart that lists any was not verified.

Sandbox
    The strict default (no network, baseline environment only). KubeLinter reads no
    environment variable ASH passes.

Install
    ASH pins v0.8.3 in ``utils/tool_downloads.py``: one release archive per platform
    (``kube-linter-<os>[_arm64].tar.gz``; the names carry no version, so a
    ``_DIGESTS_TAKEN_AT`` row records it), a SHA256 for each archive and for the
    executable inside it, and a license entry staging the archive's ``LICENSE``.
    ``ash dependencies install --tool kube-linter`` installs it, and the container image
    installs it the same way. ``kube-linter --version`` is an unknown flag;
    ``kube-linter version`` prints the bare version (``0.8.3``).
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
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import downloadable_tools

#: The release this plugin was written against and the one ASH pins (the
#: ``ToolPin`` in ``base/plugin_provisioning.py``; see the module docstring).
PINNED_VERSION = "v0.8.3"

#: The key ``utils/tool_downloads`` knows the tool by, which is also its executable.
KUBE_LINTER_TOOL_NAME = "kube-linter"

#: Exit codes KubeLinter uses that mean it ran to completion or reported problems. Exit 1
#: is both "found problems" and "failed"; see the module docstring.
SUCCESS_EXIT_CODES: Set[int] = {0, 1}

#: Checks whose finding widens what a compromised workload or identity can reach. These
#: are HIGH; every other check is MEDIUM. See "Severity" in the module docstring.
HIGH_SEVERITY_CHECKS = frozenset(
    {
        "access-to-create-pods",
        "access-to-secrets",
        "cluster-admin-role-binding",
        "docker-sock",
        "host-ipc",
        "host-network",
        "host-pid",
        "privilege-escalation-container",
        "privileged-container",
        "privileged-ports",
        "sensitive-host-mounts",
        "wildcard-in-rules",
    }
)

#: ``ruleId -> (ASH severity, SARIF level)``.
SEVERITY_HIGH: Tuple[str, Level] = ("HIGH", Level.error)
SEVERITY_MEDIUM: Tuple[str, Level] = ("MEDIUM", Level.warning)

#: The report KubeLinter would write for a run that found no Kubernetes object, which it
#: instead ends with a warning and no report.
EMPTY_REPORT: Dict[str, Any] = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "kube-linter"}}, "results": []}],
}


def severity_for_check(rule_id: Optional[str]) -> Tuple[str, Level]:
    """The ASH severity and SARIF level for a KubeLinter check name."""
    if rule_id in HIGH_SEVERITY_CHECKS:
        return SEVERITY_HIGH
    return SEVERITY_MEDIUM


class KubeLinterScannerConfigOptions(ScannerOptionsBase):
    """KubeLinter has no options of its own: ASH always runs its default checks."""


class KubeLinterScannerConfig(ScannerPluginConfigBase):
    name: Literal["kube-linter"] = "kube-linter"
    enabled: bool = True
    options: Annotated[
        KubeLinterScannerConfigOptions,
        Field(description="Configure the kube-linter scanner"),
    ] = KubeLinterScannerConfigOptions()


@ash_scanner_plugin
class KubeLinterScanner(ScannerPluginBase[KubeLinterScannerConfig]):
    """Kubernetes manifest, Helm chart and Kustomize linting using KubeLinter."""

    #: Not Python-only: KubeLinter is a native binary installed from its pinned release.
    python_only: ClassVar[bool | None] = False

    # The checks are compiled into the binary; a plain manifest scan makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = SUCCESS_EXIT_CODES
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name KubeLinter's own SARIF as the v0.8.3
    #: formatter writes it (tests/test_data/scanners/kube-linter/captured/README.md
    #: records the real run the fixtures come from). A cell the adapter does not read
    #: is n/a with the reason the register asks for.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (the check name, e.g. privileged-container)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" rated through HIGH_SEVERITY_CHECKS '
            "(the native SARIF carries no level or severity)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startLine (KubeLinter writes line 1 for every result)",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the native region carries startLine only",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text" (diagnostic, then "object: '
            '<namespace>/<name> <apiVersion>, Kind=<Kind>")',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="the object is named by the result's logicalLocations "
            "(Object Name, Object Namespace, GVK/Kind) and the message tail, "
            "but this adapter does not read either, and a value assembled from "
            "prose is an inference; fail closed",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="the object kind is in the result's logicalLocations (GVK/Kind) "
            "and the message tail, but this adapter does not read either",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="Kubernetes lint findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="Kubernetes lint findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="Kubernetes lint findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="KubeLinter checks carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="KubeLinter checks carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="a result carries only ruleId, ruleIndex, message and "
            "locations (captured/positive.sarif); no fingerprint field exists",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="lint findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the remediation is on tool.driver.rules[].fullDescription and "
            "help.text, once per check, not on the result; this adapter does "
            "not read it",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the native region carries no snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="tool.driver.rules[].helpUri (the check's docs page), read "
            "into the flat references when the result carries no relatedLocations",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="results carry no native tags; the constant 'kubernetes' and "
            "'iac' tags are added by the adapter, not read from the output",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result property "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    #: The runtime row is PINNED_BINARY: the release is pinned in
    #: utils/tool_downloads.py, and the platforms are what its table lists.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="kube-linter",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source="kube_linter_scanner.py offline_strategy, sandbox_requirements",
                unconfirmed="whether KubeLinter fetches the dependencies of a Helm "
                "chart that lists any was not read",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.IAC_KUBERNETES,),
                tool_type=ScannerToolType.IAC,
                selection="KubeLinter walks the scan path itself and renders Helm "
                "charts and Kustomize directories; a tree with no Kubernetes "
                "object is a clean run with no results",
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key=KUBE_LINTER_TOOL_NAME,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: a statically linked binary, and no runtime-compatibility
            # row was measured for KubeLinter.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_ALL,
                note="the v0.8.3 release publishes darwin, linux and windows "
                "archives for amd64 and arm64; derived from "
                "tool_downloads.supported_platforms",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="no native level; HIGH_SEVERITY_CHECKS rates by check name, "
                "everything else is MEDIUM",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="annotations on a scanned object: "
                        "ignore-check.kube-linter.io/<check> skips that check on it "
                        "and kube-linter.io/ignore-all skips every check on it; "
                        "v0.8.3 has no flag that turns either off",
                        cite="pkg/ignore/ignore.go:9-27 and pkg/run/run.go:54-62 at "
                        "v0.8.3 (commit 10ae0030): applied to every object and check "
                        "with no config or flag condition; the flags are "
                        "pkg/command/lint/command.go:207-219, "
                        "pkg/config/flags.go:13-34 and "
                        "pkg/command/root/command.go:38 (module header, Ignore "
                        "annotations)",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".kube-linter.yaml or .kube-linter.yml in the source "
                        "directory, whose checks.exclude and "
                        "checks.doNotAutoAddDefaults would switch checks off and "
                        "checks.ignorePaths would skip paths",
                        cite="pkg/config/config.go:42 and :55-62 at v0.8.3 read it "
                        "only when --config is empty; ASH always passes --config "
                        "with a stub holding {} (module header, Configuration)",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="identity is file, line and rule through the shared floor; "
                "every result sits at line 1, so two objects in one file that "
                "fail one check share an identity",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options; ASH passes a stub config so the "
                "checks are KubeLinter's defaults",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 is nothing found; 1 is found problems or failed, "
                "told apart by whether the report is on disk; any other code fails",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=("ash_kube_linter_plugins in ash_plugin_modules",),
                upstream_license=(
                    "Apache-2.0 (source: the LICENSE file inside the v0.8.3 release "
                    "archives, byte-identical across all six and to the repository "
                    "LICENSE at the tag's commit 10ae0030, read 2026-11-26)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="Kubernetes manifests, Helm charts or Kustomize directories "
                "in the scan set",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = KubeLinterScannerConfig()
        self.command = "kube-linter"
        self.subcommands = ["lint"]
        self.tool_type = ScannerToolType.IAC
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing from
        # the base resolver can add a token KubeLinter would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "KubeLinterScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``.

        The pin (version, six asset names, archive and executable digests, license
        entry) lives in that shared table, and this call turns it into one verified
        download per platform it lists. A table without the pin makes
        ``pinned_tool_install_commands`` refuse with ``ToolNotProvisionableError``;
        that refusal must not escape construction, so the table then stays empty (an
        absent platform, never an empty command list that reads as installable) and
        ``validate_plugin_dependencies`` tells the user to install the tool.
        """
        try:
            self.custom_install_commands.update(
                pinned_tool_install_commands(KUBE_LINTER_TOOL_NAME)
            )
        except ToolNotProvisionableError as exc:
            ASH_LOGGER.debug("kube-linter is not provisionable by ASH: %s", exc)
        return self

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("KubeLinterScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before KubeLinter runs whether the tree holds manifests."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the subprocess's cwd), absolute otherwise."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _stub_config(self) -> Path:
        """An empty config ASH writes, so the scanned tree's config is never read."""
        stub = (
            Path(self.results_dir or self._source_dir())
            .absolute()
            .joinpath("kube-linter-no-config.yaml")
        )
        stub.parent.mkdir(parents=True, exist_ok=True)
        with open_for_write(stub) as handle:
            handle.write("{}\n")
        return stub

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full argv: every option one ``--flag=value`` token, the path after ``--``."""
        return [
            self.command or "kube-linter",
            *self.subcommands,
            "--format=sarif",
            f"--output={results_file.as_posix()}",
            f"--config={self._stub_config().as_posix()}",
            "--",
            self._scan_path(target),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one KubeLinter run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by
        ``apply_suppressions_to_sarif``, not translated into KubeLinter config.
        """
        if self.results_dir is None:
            raise ScannerError("KubeLinterScanner has no results directory")
        # One instance scans source then converted, and the base keeps the worst exit
        # code across runs; reset so a failed source run does not fail a clean one.
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "kube-linter.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's: with exit 1
        # the report's presence is what separates "found problems" from "failed".
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """The report of a run that completed, or an empty one when none was written.

        Any code outside 0 and 1 fails. Exit 1 needs the report on disk (a missing one
        raises in the base class): without it KubeLinter failed rather than found
        problems. Exit 0 without a report is KubeLinter finding no Kubernetes object.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"kube-linter exited {self.exit_code}; it exits 0 when it finds nothing "
                "and 1 when it finds problems or fails, so this run failed"
            )
        if self.exit_code == 0 and not os.path.lexists(results_file):
            self._plugin_log(
                "kube-linter exited 0 and wrote no report: it found no Kubernetes "
                "object to lint, so nothing is reported.",
                level=logging.INFO,
            )
            return {**EMPTY_REPORT}
        return super()._read_results_file(results_file)

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where KubeLinter's log is, without quoting the log.

        KubeLinter's stderr can quote text of the scanned manifests, so it stays in the
        log file and out of the scan's error lines.
        """
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (kube-linter was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). kube-linter's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code and keep KubeLinter's stderr out of ``self.errors``."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove results located under ASH's own output directory inside ``target``.

        KubeLinter has no exclude flag on the command line, so when the output
        directory is inside the target (the default ``.ash/ash_output``) it lints ASH's
        own YAML, including the copies of files ASH converted.
        """
        if self.context is None:
            return
        inside: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            inside.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in inside:
                inside.append(relative)
        if not inside:
            return
        target_abs = Path(target).absolute()
        roots = [Path(os.path.normpath(target_abs / o)) for o in inside]

        def under_output(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if not uri:
                    continue
                path = Path(os.path.normpath(target_abs / uri))
                if any(path.is_relative_to(root) for root in roots):
                    return True
            return False

        for run in sarif_report.runs or []:
            if run.results:
                run.results = [r for r in run.results if not under_output(r)]

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, then rate every result by its check name."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            severity, level = severity_for_check(result.ruleId)
            result.level = level
            result.kind = Kind.fail
            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("kubernetes", "iac"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or KUBE_LINTER_TOOL_NAME)
        if not found:
            hint = (
                f"Install kube-linter {PINNED_VERSION} from "
                "https://github.com/stackrox/kube-linter/releases and put it on PATH "
                "(this ASH build pins no kube-linter release)."
            )
            if KUBE_LINTER_TOOL_NAME in downloadable_tools():
                hint = (
                    f"Install the pinned kube-linter {PINNED_VERSION} with "
                    "`ash dependencies install --config-overrides "
                    "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                    "ash_kube_linter_plugins\"]' --tool kube-linter`."
                )
            ASH_LOGGER.warning(f"kube-linter executable not found in PATH. {hint}")
        return found is not None


__all__ = [
    "EMPTY_REPORT",
    "HIGH_SEVERITY_CHECKS",
    "KUBE_LINTER_TOOL_NAME",
    "KubeLinterScanner",
    "KubeLinterScannerConfig",
    "KubeLinterScannerConfigOptions",
    "SUCCESS_EXIT_CODES",
    "severity_for_check",
]
