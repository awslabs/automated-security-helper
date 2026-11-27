# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, ClassVar, List, Literal, Optional, Set
from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.models.vocab import TargetType
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.tool_config_trust import empty_tool_directory
from automated_security_helper.models.core import ToolArgs

# trivy_default_misconfig_scanners and its reset live with the shared base, which
# the builtin trivy uses too; this module has always offered them, so it still does.
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    TRIVY_SARIF_FACETS,
    TrivyScannerBase,
    reset_trivy_default_misconfig_scanners as reset_trivy_default_misconfig_scanners,
    trivy_default_misconfig_scanners,
    trivy_timeout,
)
from automated_security_helper.base.scanner_plugin import (
    redacted_command_record,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.schemas.scanner_output_ingest import (
    ingest_sarif,
    read_json_tolerant,
)
from automated_security_helper.base.uv_tool_mixin import guarded_values_read
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import VERBOSE_LEVEL
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.process_env import snapshot_environ


class TrivyRepoScannerConfigOptions(ScannerOptionsBase):
    scanners: Annotated[
        List[Literal["vuln", "misconfig", "secret", "license"]],
        Field(
            description="List of what security issues to detect with Trivy Repo specifically",
        ),
    ] = [
        "vuln",
        "secret",
        "misconfig",
        "license",
    ]
    license_full: Annotated[
        bool,
        Field(
            description="Eagerly look for licenses in source code headers and license files",
        ),
    ] = True
    ignore_unfixed: Annotated[
        bool,
        Field(
            description="Display only fixed vulnerabilities",
        ),
    ] = True
    disable_telemetry: Annotated[
        bool,
        Field(
            description=(
                "Disable sending anonymous usage data to Aqua (--disable-telemetry). "
                "Only the operator sets it to false, with --config-overrides or in a "
                "config file outside every git checkout and the scanned directory: a "
                "config file inside one, or one an MCP client delivered, may set it "
                "to true but not to false. Offline, trivy sends none whatever this "
                "says."
            ),
        ),
    ] = True
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, skipping DB updates and check-update calls. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy config file (trivy.yaml), passed as --config. "
                f"{SET_BY_THE_OPERATOR} The file is used only when it is outside the "
                "scanned tree; otherwise it is ignored with a warning. A relative "
                "path is taken from the directory of the config "
                "file that sets it, or from the working directory for "
                "--config-overrides, not from the source directory. Unset or "
                "ignored, ASH passes TRIVY_CONFIG when that names a file outside the "
                "scanned tree (a relative path in it is taken from the working "
                "directory), and otherwise an empty config of its own, so trivy "
                "does not load a trivy.yaml from the directory it runs in. A path "
                "that does not exist fails the scan."
            ),
        ),
    ] = None
    module_dir: Annotated[
        Path | str | None,
        Field(
            description=(
                "A directory of trivy modules, passed as --module-dir. Unset, ASH "
                f"passes an empty directory of its own. {SET_BY_THE_OPERATOR} The "
                "directory is used, and a relative path taken, as for config_file. A "
                "path that is not a directory fails the scan."
            ),
        ),
    ] = None

    ignore_file: Annotated[
        str | None,
        Field(
            description=(
                f"A trivy ignore file, passed as --ignorefile. {SET_BY_THE_OPERATOR} "
                "The file is used only when it is outside the scanned tree; a "
                "relative path is taken from the directory of the config file that "
                "sets it, or from the working directory for --config-overrides and "
                "the environment variable. "
                "Unset, TRIVY_IGNOREFILE is used the same way, and "
                "otherwise trivy gets an empty one, so a .trivyignore in the scanned "
                "repository does not remove findings."
            ),
        ),
    ] = None
    secret_config_file: Annotated[
        str | None,
        Field(
            description=(
                "A trivy secret scanning config (trivy-secret.yaml), passed as "
                f"--secret-config. {SET_BY_THE_OPERATOR} The file is used only when "
                "it is outside the scanned tree; a relative path is taken from the "
                "directory of the config file that sets it, or from the working "
                "directory for --config-overrides and the environment variable. Unset, "
                "TRIVY_SECRET_CONFIG is used the same way, and otherwise trivy gets "
                "an empty one, so a trivy-secret.yaml in the scanned repository does "
                "not disable secret rules."
            ),
        ),
    ] = None


class TrivyRepoScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Trivy Repo scanner."""

    name: Literal["trivy-repo"] = "trivy-repo"
    enabled: bool = True
    options: Annotated[
        TrivyRepoScannerConfigOptions,
        Field(description="Configure trivy-repo scanner"),
    ] = TrivyRepoScannerConfigOptions()


@ash_scanner_plugin
class TrivyRepoScanner(TrivyScannerBase[TrivyRepoScannerConfig]):
    """Trivy repo scanner plugin.

    The option-to-flag mapping, install commands and package identity are shared
    with the ``trivy`` scanner of this module through ``TrivyScannerBase``; this class
    keeps its own config and its own ``scan()``. Its names and output files are
    unchanged; its results carry trivy's own severity, and its command ASH's scan
    timeout as trivy's deadline and ``--skip-dirs`` for ASH's output directories,
    as the builtin scanner's do.
    """

    #: trivy is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    # trivy exits 0 for a completed run, findings or not, unless --exit-code names
    # another code for findings (default 0, pkg/flag/report_flags.go), and 1 from
    # log.Fatal on any error (cmd/trivy/main.go). TrivyScannerBase._run_subprocess
    # passes --exit-code=0, which outranks TRIVY_EXIT_CODE and a trivy.yaml, so a
    # nonzero exit only ever means trivy failed.
    success_exit_codes: ClassVar[Set[int]] = {0}

    #: The facets register row (base/scanner_facets.py). Declaration only.
    #: trivy-repo shares trivy's SARIF reading through TrivyScannerBase but
    #: classifies its own output: its default scanners are vuln, secret,
    #: misconfig and license, so the misconfig resource facet applies to its
    #: DEFAULT run (M0 settled it: the address exists natively in JSON and
    #: dies at the SARIF format ASH reads).
    #: Native fields are quoted from the committed trivy SARIF
    #: (tests/test_data/scanners/trivy/trivy-0.69.3.vuln.sarif) and from the
    #: M0 misconfig capture (tests/test_data/scanners/trivy/captured/
    #: trivy-0.76.2-misconfig-terraform.{json,sarif}, M0-FINDINGS.md (a)).
    #: Its cells are the shared TRIVY_SARIF_FACETS (vulnerability results, and
    #: the terraform misconfiguration resource id); secret and license results
    #: are not classified by any committed capture. Only fix_available differs.
    facets: ClassVar[ScannerFacets] = TRIVY_SARIF_FACETS.model_copy(
        update={
            "fix_available": FacetDecl(
                state=FacetState.MAPPED,
                native_field='message line "Fixed Version: <version>", written as '
                "fix_available=True when non-empty by "
                "TrivyScannerBase._fixed_version_from_message (an empty value "
                "writes nothing; ignore_unfixed defaults to true, so the tool "
                "pre-filters unfixed findings)",
            ),
        }
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="trivy-repo",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(
                    opsf.Fetched.VULN_DB,
                    opsf.Fetched.CHECKS_BUNDLE,
                    opsf.Fetched.MODULE_SOURCES,
                ),
                prefetch=(opsf.Prefetch.CONTENT_DB_REFRESH,),
                offline_outcome=opsf.OfflineOutcome.DEGRADED,
                offline_reason=(
                    "--skip-db-update, --skip-java-db-update and --skip-check-update "
                    "against the cached databases; Terraform checks are removed from the "
                    "misconfiguration set offline with the reason logged; a scan that "
                    "reads the vulnerability database with none cached is refused before "
                    "the scan"
                ),
                offline_strategy=OfflineStrategy.CACHE_FLAGS,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                content_database="trivy-db",
                source=(
                    "_trivy_scanner_base.py offline_strategy, sandbox_requirements, "
                    "SCAN_FLAGS and OFFLINE_FLAGS; utils/content_databases.py trivy-db "
                    "(declared for trivy-repo)"
                ),
                unconfirmed=(
                    "the default scanner set is all four, so the online Terraform module "
                    "fetch and the offline misconfig degradation apply by default here, "
                    "unlike the builtin trivy scanner"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(
                    opsf.TargetKind.DEPENDENCY_LOCKFILES,
                    opsf.TargetKind.SECRETS_CONTENTS,
                    opsf.TargetKind.IAC_TERRAFORM,
                    opsf.TargetKind.IAC_KUBERNETES,
                    opsf.TargetKind.IAC_CLOUDFORMATION,
                    opsf.TargetKind.DOCKERFILES,
                ),
                tool_type=ScannerToolType.SCA,
                selection="`trivy repository` over the target; scanners default to vuln, secret, misconfig and license",
                covers_note="an alpha scanner; it declares no covers display string",
                tool_type_note=(
                    "was SAST, which contradicted what it runs (vuln, secret, misconfig "
                    "and license scanners, no source analysis) and fed the reporter-side "
                    "scanner-type exclusions the wrong type; corrected to SCA, the type "
                    "the builtin trivy scanner declares"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key="trivy",
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_NO_WINDOWS_ARM64,
                note="no windows/arm64 and no 32-bit macOS asset (tool_downloads.py docstring)",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="issue_severity is computed from the message and tags",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.TOOL_DEFAULT_FILTER,
                        writer=opsf.SilencingWriter.TOOL_DEFAULT,
                        honored=opsf.Honored.YES,
                        surface="options.ignore_unfixed defaults to True and pre-filters tool-side",
                        cite="trivy_repo_scanner.py ignore_unfixed option and the warning at :273",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.UNCONFIRMED,
                        surface="a trivy ignore file in the scanned tree",
                        cite="tool feature; _trivy_scanner_base.py lists TRIVY_IGNORE_* and TRIVY_SKIP_* as passed-through variables",
                        reason=(
                            "whether a repository-written ignore file can silence findings "
                            "under ASH was not read; one adapter read settles it"
                        ),
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="identity is file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("TRIVY_",),
                options_surface="typed options (scanners, ignore_unfixed, license_full); ASH always passes its own --config",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="trivy reports findings in the file, not through its exit code",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=(
                    "ash_trivy_plugins in ash_plugin_modules",
                    "options.scanners (all four on by default)",
                ),
                upstream_license=(
                    "Apache-2.0 (source: utils/tool_downloads.py "
                    "THIRD_PARTY_LICENSES['trivy'], pinned commit 3f6334d; the "
                    "trivy binary this plugin invokes)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="a directory",
            ),
        )
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = TrivyRepoScannerConfig()
        self.command = "trivy"
        self.subcommands = ["repository"]
        # SCA, not SAST: it runs the vuln, secret, misconfig and license
        # scanners and no source analysis (operational_facets.targets).
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def _process_config_options(self):
        self._append_trivy_options()
        if self.config.options.ignore_unfixed:
            # The default here, unlike the builtin trivy scanner's, so every default
            # run says once what it withholds, as grype's config warning does. Once
            # per scanner (_warned_inputs), however often the options are read, and
            # as set: "the default" only when the option was not written.
            written = "ignore_unfixed" in self.config.options.model_fields_set
            warning = (
                "scanners.trivy-repo.options.ignore_unfixed is true "
                f"({'set in the configuration' if written else 'the default'}), "
                "which restricts which vulnerabilities reach the report: those with "
                "no fixed version are withheld, and the scan can pass with them "
                "present. Set it to false to report them."
            )
            if warning not in self._warned_inputs:
                self._warned_inputs.add(warning)
                self._plugin_log(warning, level=logging.WARNING)
        return super()._process_config_options()

    def _default_misconfig_scanners(self, binary: str) -> Optional[List[str]]:
        """``TrivyScannerBase._default_misconfig_scanners``, looked up in this module.

        Through this module's ``trivy_default_misconfig_scanners``, the name
        trivy-repo's callers have always used (and replaced, in its tests), rather
        than the base module's; both name the same function.
        """
        return trivy_default_misconfig_scanners(binary, list(self.subcommands))

    def _pinned_config_args(self) -> List[str]:
        """``--config`` and ``--module-dir``, so trivy loads neither from where it runs.

        trivy runs with the scan target as its working directory and loads a
        ``trivy.yaml`` from there unless ``--config`` names another, and loads the
        modules in ``--module-dir`` (or the config's ``module.dir``). Both are
        always passed. The config is ``TrivyScannerBase._trivy_config_file``'s, as
        for ``trivy``: the operator's ``config_file`` or ``TRIVY_CONFIG``, else the
        empty config ASH ships. The modules directory is the operator's, when
        ``_operator_path`` accepts it, and otherwise an empty one that ASH creates
        outside the scanned tree for this run (``empty_tool_directory``), new each
        time and removed when the run ends.
        """
        options = self.config.options
        config_file = self._trivy_config_file()
        module_dir: Optional[Path] = None
        if options.module_dir:
            module_dir = self._operator_path(
                "module_dir",
                options.module_dir,
                "trivy-repo runs with an empty modules directory instead.",
            )
            if module_dir is not None and not module_dir.is_dir():
                # Key only, as the other input refusals (_existing_file): an
                # option's value can come from the environment, and the path it
                # resolved to spells that value.
                raise ScannerError(
                    "scanners.trivy-repo.options.module_dir does not name a "
                    "directory: the path it is set to does not exist or is not a "
                    "directory. Fix the path or unset the option; trivy is not run "
                    "without it."
                )
        if module_dir is None:
            module_dir = empty_tool_directory("trivy-modules", context=self.context)
        return [
            f"--config={config_file}",
            f"--module-dir={module_dir.resolve().as_posix()}",
        ]

    def content_databases_in_use(self) -> list:
        """trivy-db, unless the scan's effective scanners leave out ``vuln``.

        The secret, misconfiguration and license scanners never open it. The set
        is read as trivy reads it (``TrivyScannerBase._effective_scanners``: the
        option, else ``TRIVY_SCANNERS``, else the config file's ``scan.scanners``,
        else trivy's own ``vuln,secret`` default), the same reading the database
        update is gated on: a run whose scanners never open the database skips the
        update, and must not then be held to that database's age.
        """
        if "vuln" not in self._effective_scanners():
            return []
        return super().content_databases_in_use()

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — TrivyRepoScanner overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[Any] | None = None,
        config: Any | None = None,
        *args,
        **kwargs,
    ) -> SarifReport | bool | None:
        """Run ``trivy repository`` on the target and return its SARIF report.

        The parameters are in the base ``scan()``'s order (target, target type,
        the global ignore paths, then the config), so a caller that passes them by
        position as the base declares them is read right; the executor passes
        them by keyword.

        Args:
            target: Target file or directory to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: List of paths to ignore
            config: Scanner configuration

        Returns:
            The SarifReport trivy wrote; True for an empty target; False when trivy
            cannot run; None when trivy wrote no readable SARIF.
        """
        # Per target; see ScannerPluginBase.scan(). The tool lines too: a failed
        # converted-target run otherwise records the source target's stderr as its
        # own (exitCodeDescription).
        self.exit_code = 0
        self.output = []
        self._reset_errors()
        # What reading this target's report repairs, started again for each target
        # for the same reason.
        self._start_ingest_record()
        global_ignore_paths = list(global_ignore_paths or [])
        # Check if the target directory is empty or doesn't exist
        if self._target_is_empty(target):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            # No tool runs for this target, so its record starts and ends now: a
            # start time left from the previous target would give it that
            # target's duration.
            self.start_time = None
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return True

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        # No exit code until trivy returns one, as the template's scan() has it: a
        # scan refused before the tool starts reports none, not the 0 set above.
        self.exit_code = None

        # Set by the except block below; declared here so a way out of the try body
        # that neither returns nor raises cannot reach the final raise unbound.
        failure: Optional[str] = None
        # The refusal ScannerPluginBase._refuse_flagged_response raises for a run the
        # subprocess layer flagged, once it has. Its text was shaped through the
        # one guarded read of the values hook, so the handler below re-raises it
        # as it is instead of building a second message from it.
        flagged_refusal: Optional[ScannerError] = None
        try:
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)
            # A report left by an earlier run must not be read as this run's: trivy
            # writes none when it fails, and the read below takes whatever is here.
            results_file.unlink(missing_ok=True)

            final_args = self._resolve_arguments(
                target=target,
                results_file=results_file,
            )
            # Right after `trivy repository`, which needs no knowledge of how the
            # target is spelled further on; trivy takes flags in any position.
            head = [self.command, *self.subcommands]
            insert_at = (
                len(head) if final_args[: len(head)] == head else len(final_args)
            )
            # The --config token first: the secret config is read by the secret
            # scanner alone, and whether that scanner runs is read through the
            # config file the run passes (TrivyScannerBase._effective_scanners).
            pinned = self._pinned_config_args()
            # ASH's own output directories inside the target, as the builtin
            # trivy scanner skips them: the converted copies the converted
            # target scans already, and an earlier run's reports and results.
            output_dir_args = self._output_dir_skip_args(target, target_type)
            # The operator's own skip entries are sized first and kept out of the
            # links' share of the argument budget
            # (TrivyScannerBase._operator_skip_plan): ASH's tokens have a fallback
            # when left out, the operator's have none.
            operator_skips = self._operator_skip_plan([*pinned, *output_dir_args])
            inserted = [
                f"--ignorefile={self._ignore_file()}",
                f"--secret-config={self._secret_config_file(pinned)}",
                *pinned,
                # trivy's own deadline is five minutes and fails the scan when it
                # passes; matched to ASH's scan_timeout, as the builtin trivy scanner
                # does, so the bound the operator set is the one that applies.
                f"--timeout={trivy_timeout(self._effective_scan_timeout())}",
                # Each link leaving the target (trivy follows no link), and each
                # path the global ignore paths ignore.
                *self._ashs_skip_args(
                    target,
                    global_ignore_paths,
                    operator_skips,
                    target_type=target_type,
                ),
                *output_dir_args,
            ]
            # The operator's own skip lists, which ASH's skip flags would
            # otherwise replace (TrivyScannerBase._operator_skip_args).
            inserted.extend(
                self._operator_skip_args(
                    inserted, operator_skips, target_type=target_type
                )
            )
            final_args[insert_at:insert_at] = inserted
            if self._offline():
                final_args = self._offline_misconfig_args(final_args)
            subprocess_env = (
                {**snapshot_environ(), **self.extra_env} if self.extra_env else None
            )
            # The database update, its skip flags and --cache-backend=memory are
            # added by TrivyScannerBase._run_subprocess, for trivy and trivy-repo
            # alike (utils/content_db_refresh.py), IN PLACE on final_args: the
            # SARIF invocation is recorded after the run, below, so it carries the
            # command that ran rather than the one assembled here.

            # The values hook is overridable and is read once, guarded, for the
            # log line and both SARIF records. When it raised or gave no usable
            # answer nothing can be redacted, so every record carries only the
            # command's name.
            read = guarded_values_read(self)
            redact_values = read.values
            if redact_values is None:
                self._plugin_log(
                    f"Running command: {self.command} (the arguments are not "
                    f"shown: the plugin's values hook {read.failure()})",
                    target_type=target_type,
                    level=VERBOSE_LEVEL,
                )
            else:
                self._plugin_log(
                    "Running command: "
                    f"{text_without_values(' '.join(final_args), redact_values)}",
                    target_type=target_type,
                    level=VERBOSE_LEVEL,
                )

            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                env=subprocess_env,
                timeout=effective_timeout,
            )
            # The run is over: its end time is recorded here, before the invocation
            # below reads it, so the first target's record carries this run's end
            # rather than None and the second's rather than the first's.
            self._post_scan(target=target, target_type=target_type)
            # The command as it ran, with the flags _run_subprocess added in place.
            if redact_values is None:
                shown_command = str(self.command)
                recorded_command_line = shown_command
                recorded_arguments: List[str] = []
            else:
                shown_command = text_without_values(" ".join(final_args), redact_values)
                recorded_command_line, recorded_arguments = redacted_command_record(
                    final_args, redact_values
                )
            # A run the subprocess layer flagged (timed out, could not start, its
            # output not recorded, ended by a foreign signal) is refused before its
            # file is read, whatever exit code it carries.
            try:
                self._refuse_flagged_response(response, effective_timeout)
            except ScannerError as refusal:
                flagged_refusal = refusal
                raise
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code(results_file)

            # SARIF mode - parse SARIF results
            if Path(results_file).exists():
                # Read as bytes and parsed tolerantly: a byte-order mark, a byte
                # that is not UTF-8 and a control character inside a string are
                # read as the tool meant them and noted on the scanner's record.
                with open(results_file, mode="rb") as f:
                    scanner_results = read_json_tolerant(f.read(), self._ingest_record)
                # Only the validation sits in this try: an error raised after the
                # SARIF validated (attaching the package identity, building the
                # invocation) is ASH's own and is reported as what it is by the
                # handler below, not as a results file that is not SARIF.
                try:
                    # The smallest out-of-spec part is dropped or rewritten and
                    # the other findings are kept (schemas.scanner_output_ingest).
                    sarif_report: SarifReport = ingest_sarif(
                        scanner_results, self._ingest_record
                    )
                except Exception as e:
                    # Refused, not returned as no result: the row would then read
                    # only "returned no result". error_text names the field and
                    # the problem and quotes no input.
                    raise ScannerError(
                        "trivy's results file is not SARIF ASH can read, so its "
                        f"findings could not be graded: {error_text(e)}"
                    )
                self._say_what_the_ingest_repaired(target_type)
                sarif_report = self._attach_package_identity(sarif_report, target)
                sarif_report = self._attach_misconfig_resources(
                    sarif_report, final_args
                )
                # trivy's own per-result severity, as the builtin trivy scanner
                # reports it: without it ASH buckets the CVE rule's last CVSS
                # score, which is another package's rating for the same CVE.
                sarif_report = self._attach_trivy_severity(sarif_report)

                # Attach scanner details for proper identification
                sarif_report = attach_scanner_details(
                    sarif_report=sarif_report,
                    scanner_name=self.config.name,
                    scanner_version=getattr(self, "tool_version", None),
                    invocation_details={
                        "command_line": shown_command,
                        "arguments": recorded_arguments,
                        "working_directory": get_shortest_name(input=target),
                        "start_time": self.start_time.isoformat()
                        if self.start_time
                        else None,
                        "end_time": self.end_time.isoformat()
                        if self.end_time
                        else None,
                        "exit_code": self.exit_code,
                    },
                )

                if sarif_report.runs:
                    sarif_report.runs[0].invocations = [
                        # What reading the file repaired is said in the report as
                        # a warning, which fails no run.
                        self._noting_the_ingest(
                            Invocation(
                                commandLine=recorded_command_line,
                                arguments=recorded_arguments,
                                startTimeUtc=self.start_time,
                                endTimeUtc=self.end_time,
                                executionSuccessful=self._exit_code_accepted(),
                                exitCode=self.exit_code,
                                exitCodeDescription="\n".join(self.errors),
                                workingDirectory=ArtifactLocation(
                                    uri=get_shortest_name(input=target),
                                ),
                            )
                        )
                    ]
                return sarif_report
            else:
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )
                return None

        except Exception as e:
            # The run is over for this target, however it ended: the executor
            # records end_time, and one left from the previous target would give
            # this one an end before its start.
            self.end_time = datetime.now(timezone.utc)
            # A flagged run is reported as the base method worded it: building a
            # message from it here would swap its value-free headline for the
            # generic failed text when the values hook gave no usable answer.
            if e is flagged_refusal:
                raise
            # Redacted, as the syft scanner's catch-all is: the text can quote a
            # path the configuration read from the environment (an OSError naming
            # the TRIVY_SECRET_CONFIG or TRIVY_IGNOREFILE file). Through the same
            # guarded read as the command record above, so a values hook that
            # raises does not replace this error with its own; with no usable
            # answer nothing can be redacted, and the error text is not shown.
            read = guarded_values_read(self)
            if read.values is None:
                failure = (
                    "Trivy scan failed (the error text is not shown: the plugin's "
                    f"values hook {read.failure()})"
                )
            else:
                failure = text_without_values(
                    f"Trivy scan failed: {str(e)}", read.values
                )
        # Raised outside the except block, so the original exception, whose text
        # is not redacted, is attached to the new one neither as __context__ nor
        # as __cause__: `raise ... from None` would only hide it from the default
        # traceback while leaving it readable on the object. Every other exit of
        # the try body returns, so this line is reached from the except alone; a
        # future exit that falls through gets the generic text, not an unbound name.
        raise ScannerError(failure or "Trivy scan failed")
