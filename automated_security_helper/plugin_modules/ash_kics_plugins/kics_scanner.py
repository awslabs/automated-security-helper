# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""KICS (Keeping Infrastructure as Code Secure) as an ASH community scanner.

What it runs
------------
``kics scan`` over the scan target. KICS reads infrastructure-as-code of sixteen
platforms (Terraform, CloudFormation, Kubernetes, Ansible, OpenAPI, Pulumi, Azure
Resource Manager, Google Deployment Manager, Dockerfile, Docker Compose, Crossplane,
Knative, Serverless Framework, Buildah, gRPC and CI/CD files) and evaluates its Rego
queries over them. It overlaps checkov and the other IaC scanners ASH ships; it is
the only one that reads OpenAPI, Pulumi, ARM and Bicep-style inputs among them. A
scan that does not list this plugin module is unchanged.

This is the template-scanner shape (``_execute_scan``): one invocation per target
that writes its report files, which the base ``scan()`` then reads.

Invocation (measured on KICS v2.1.20, the pinned release)
---------------------------------------------------------
``kics scan --no-progress --no-color --silent --disable-secrets
--ignore-on-exit=results --exclude-gitignore --report-formats=json,sarif
--output-name=kics --output-path=<dir> --config=<empty stub>
--queries-path=<assets>/queries --libraries-path=<assets>/libraries
[--exclude-paths=<ASH output dir>] --path=<target>``

Every option is one ``--flag=value`` token, so no path is read as a flag.

* ``--report-formats=json,sarif``: the SARIF report puts the severity on the RULE
  (``defaultConfiguration.level``) and not on the result, and maps both CRITICAL and
  HIGH to ``error``, INFO to ``none``. The JSON report beside it names every query's
  exact severity (``queries[].severity``), which is what ASH rates a result by. See
  "Severity".
* ``--ignore-on-exit=results``: without it KICS exits 60/50/40/30/20 for the worst
  severity it found (CRITICAL/HIGH/MEDIUM/LOW/INFO) and 126 for an engine error,
  70 for a remediation error and 130 for an interrupt. With it a scan that found
  things exits 0 and only an engine error exits non-zero, so ``success_exit_codes``
  is ``{0}`` and any other code fails the scan, whatever report is on disk.
* ``--disable-secrets``: KICS' own secret detection is a different scanner's job
  (ASH has gitleaks and detect-secrets) and would print matches into KICS' logs.
* ``--exclude-gitignore``: by default KICS skips every path a ``.gitignore`` in the
  scanned tree names. The tree would then decide what is scanned, so the flag is
  always passed. (Measured: a ``.gitignore`` naming ``main.tf`` gave 0 results
  without it and 5 with it.)
* ``--config=<stub>``: KICS loads a ``kics.config`` from the scanned directory on its
  own (measured: a ``kics.config`` with ``exclude-paths`` dropped every finding).
  ASH always passes an explicit, empty ``{}`` config it writes outside the tree, which
  takes precedence (measured: 5 results with the stub, 0 without it).
* ``--queries-path`` and ``--libraries-path``: the release archive holds only the
  binary. The queries and libraries come from the same release's ``assets``
  directory, installed next to the binary (see "Install"). Without them KICS exits
  126 with "unable to find queries".
* ``--exclude-paths=<dir>``: KICS walks the whole target, so ASH's own output
  directory inside the source tree is excluded by absolute path (measured to match).
* ``--path`` is the target. The working directory is the source directory, so report
  URIs come out source-relative.

KICS makes no network call that ASH depends on. Its crash reporter can reach
sentry.io; the scanner sandbox grants no network, so it cannot.

Not controllable (limits)
-------------------------
KICS honors inline ``# kics-scan ignore`` and ``# kics-scan disable=<query-id>``
comments in the scanned files (measured: ``# kics-scan ignore`` at the top of a
Terraform file dropped all five findings). KICS 2.1.20 has no flag that turns this
off, so a scanned repository can hide its own findings from this scanner. ASH
suppressions are the reported route; the docs page says so.

Severity
--------
CRITICAL -> CRITICAL / ``error``; HIGH -> HIGH / ``error``; MEDIUM -> MEDIUM /
``warning``; LOW -> LOW / ``note``; INFO and TRACE -> INFO / ``none``. HIGH is not
rated CRITICAL: these are misconfigurations, and KICS itself distinguishes the two.
The exact severity is read from the JSON report by query id. If that report cannot be
read, each result is rated from its rule's SARIF level instead (``error`` ->
CRITICAL, ``warning`` -> MEDIUM, ``note`` -> LOW, ``none`` -> INFO): the level cannot
tell CRITICAL from HIGH, and the more severe reading is the one used. A warning says so.

Install
-------
The release archive holds the ``kics`` binary only. The pinned ``assets`` (queries
and libraries) are a second pinned download that is unpacked into ``assets`` beside
the binary (or ``../share/kics/assets``); ASH looks in those two places. v2.1.20 is
the newest KICS release that publishes binary archives (v2.1.21 to v2.2.1 publish
none), so the pin is that release.

Sandbox
-------
The strict default: no network, baseline environment only.
"""

from __future__ import annotations

import json
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
from automated_security_helper.utils.sandbox.fs_guard import (
    open_for_write,
    read_bytes_at_most,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Name of the report files KICS writes (``kics.sarif`` and ``kics.json``).
REPORT_NAME = "kics"

#: The most of the JSON report ASH reads for its severities.
_JSON_READ_LIMIT = 256 * 1024 * 1024

#: KICS severity -> (ASH severity, SARIF level, SARIF kind).
KICS_SEVERITY_MAP: Dict[str, Tuple[str, Level, Kind]] = {
    "CRITICAL": ("CRITICAL", Level.error, Kind.fail),
    "HIGH": ("HIGH", Level.error, Kind.fail),
    "MEDIUM": ("MEDIUM", Level.warning, Kind.fail),
    "LOW": ("LOW", Level.note, Kind.fail),
    "INFO": ("INFO", Level.none, Kind.informational),
    "TRACE": ("INFO", Level.none, Kind.informational),
}

#: Used only when the JSON report cannot be read: the rule's SARIF level to a KICS
#: severity. ``error`` covers CRITICAL and HIGH, so it takes the more severe one.
RULE_LEVEL_FALLBACK: Dict[str, str] = {
    "error": "CRITICAL",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

#: Where, relative to the directory of the ``kics`` executable, the pinned
#: ``assets`` directory (holding ``queries`` and ``libraries``) is looked for.
ASSET_DIR_CANDIDATES = (
    Path("assets"),
    Path("..") / "share" / "kics" / "assets",
)


class KicsScannerConfigOptions(ScannerOptionsBase):
    """KICS has no options beyond the ones every scanner has.

    The queries, the config and the ignore handling are fixed by ASH so the scanned
    tree cannot choose them; there is nothing here for the tree to set.
    """


class KicsScannerConfig(ScannerPluginConfigBase):
    name: Literal["kics"] = "kics"
    enabled: bool = True
    options: Annotated[
        KicsScannerConfigOptions,
        Field(description="Configure the kics scanner"),
    ] = KicsScannerConfigOptions()


@ash_scanner_plugin
class KicsScanner(ScannerPluginBase[KicsScannerConfig]):
    """Infrastructure-as-code misconfiguration scanning using KICS."""

    #: Not Python-only: KICS is a native binary.
    python_only: ClassVar[bool | None] = False

    # The queries are installed with the binary and ``kics scan`` makes no network
    # call that its results depend on.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # ``--ignore-on-exit=results`` makes "found something" exit 0. Anything else
    # (126 engine error, 70, 130) is a run that did not finish.
    success_exit_codes: ClassVar[Set[int]] = {0}

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: native fields name KICS v2.1.20's SARIF and JSON reports as captured in
    #: tests/test_data/scanners/kics/captured (see its README.md); the SARIF is
    #: what the shared pipeline reads, the JSON beside it is read for severity.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="SARIF result ruleId (the KICS query id, a UUID)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="JSON report queries[].severity (CRITICAL..TRACE), joined "
            "to the SARIF result by query_id; the SARIF carries only a rule-level "
            "defaultConfiguration.level",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="SARIF result locations[].physicalLocation."
            "artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="SARIF result locations[].physicalLocation.region."
            "startLine (no endLine is written)",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="KICS regions carry startLine only (captured positive.sarif)",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="SARIF result message.text (the actual value, e.g. "
            "'acl' is equal 'public-read')",
        ),
        resource_id=FacetDecl(
            state=FacetState.DROPPED,
            native_field="JSON report queries[].files[].search_key "
            "(e.g. aws_s3_bucket[b].acl=public-read)",
            reason="the JSON report is read for severity only; search_key is a "
            "query-specific locator that includes an attribute path, and "
            "resource_name is the name attribute for some queries and 'n/a' "
            "for others, so neither is a stable resource id as it stands",
        ),
        resource_type=FacetDecl(
            state=FacetState.DROPPED,
            native_field="JSON report queries[].files[].resource_type "
            "(e.g. aws_s3_bucket)",
            reason="the JSON report is read for severity only; the value is "
            "'n/a' for queries that report an absent resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="infrastructure-as-code findings name no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="infrastructure-as-code findings name no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="infrastructure-as-code findings name no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="misconfiguration queries carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.DROPPED,
            native_field='JSON report queries[].cwe (e.g. "732")',
            reason="the JSON report is read for severity only; the SARIF "
            "relationships point at KICS' own category taxonomy, not at CWE",
        ),
        fingerprints=FacetDecl(
            state=FacetState.DROPPED,
            native_field="JSON report queries[].files[].similarity_id (a sha256)",
            reason="the JSON report is read for severity only; the SARIF "
            "results carry no partialFingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="KICS reports expected and actual values, not a fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.DROPPED,
            native_field="JSON report queries[].files[].expected_value "
            "(e.g. 'acl' should equal to 'private')",
            reason="the JSON report is read for severity only",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="KICS regions carry no snippet in either report "
            "(captured positive.sarif and positive.json)",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field="SARIF rule helpUri (the provider documentation page "
            "for the resource the query checks)",
            reason="the shared pipeline does not read a rule's helpUri into the "
            "flat references column; observed 0 of 5 results over the captured "
            "reports",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="KICS writes no tags in either report; the adapter adds the "
            "'iac' tag after the read, so the raw output carries none",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="SARIF result message.properties (platform, riskScore) "
            "and rule properties.riskScore; the adapter adds issue_severity",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="kics",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source="kics_scanner.py offline_strategy, sandbox_requirements; "
                "the queries are installed beside the binary",
                unconfirmed="KICS' crash reporter can reach sentry.io; the "
                "sandbox grants no network, so it cannot, and a run outside the "
                "sandbox was not observed with a packet capture",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=("kics.json",),
                non_finding_artifacts=(),
                note="the JSON report beside the SARIF is read for the per-query "
                "severity join",
            ),
            targets=opsf.TargetsFacet(
                kinds=(
                    opsf.TargetKind.IAC_TERRAFORM,
                    opsf.TargetKind.IAC_CLOUDFORMATION,
                    opsf.TargetKind.IAC_KUBERNETES,
                    opsf.TargetKind.IAC_OTHER,
                    opsf.TargetKind.DOCKERFILES,
                ),
                tool_type=ScannerToolType.IAC,
                selection="KICS walks the whole target itself and picks the "
                "files of the platforms it reads (Terraform, CloudFormation, "
                "Kubernetes, Ansible, OpenAPI, Pulumi, ARM, Dockerfile, Compose "
                "and others); nothing_to_scan_reason is None",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one kics scan per target (source, converted)",
                tool_versions_key="kics",
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_ALL,
                note="the release publishes all six platform archives; the "
                "pinned download rows are the integration lane's central edit",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the exact per-query severity is joined in from the JSON "
                "report; the SARIF level alone cannot tell CRITICAL from HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="# kics-scan ignore and # kics-scan "
                        "disable=<query-id> comments in the scanned files; "
                        "v2.1.20 has no flag that turns them off",
                        cite="kics_scanner.py module header, Not controllable",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="a kics.config in the scanned directory and the "
                        ".gitignore paths: ASH passes an explicit empty --config "
                        "and --exclude-gitignore",
                        cite="kics_scanner.py module header, Invocation",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the JSON report carries a similarity_id per finding that "
                "ASH does not read; the SARIF has none, so identity is file and "
                "line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="no options: the queries, config and ignore "
                "handling are fixed by ASH so the scanned tree cannot choose "
                "them",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="with --ignore-on-exit=results a completed run exits "
                "0 whatever it found; 126 (engine error), 70 and 130 fail the "
                "scan",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=("ash_kics_plugins in ash_plugin_modules",),
                upstream_license="Apache-2.0 (source: the pinned KICS v2.1.20 "
                "LICENSE, read in the release archive)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="infrastructure-as-code files in the scan set; the queries "
                "must sit beside the binary",
            ),
        )
    )

    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = KicsScannerConfig()
        self.command = "kics"
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.IAC
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token KICS would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "KicsScanner":
        """Install from the pinned release in ``utils/tool_downloads.py``.

        The ``kics`` rows are a central edit the integration lane makes (see the
        plugin's README). Until they exist the scanner still constructs, with no
        install command: a missing row must not make the scanner unconstructible,
        because that breaks discovery for every scan that lists the module.
        """
        try:
            self.custom_install_commands.update(pinned_tool_install_commands("kics"))
        except ToolNotProvisionableError:
            ASH_LOGGER.debug(
                "kics has no pinned download rows yet; `ash dependencies install "
                "--tool kics` has nothing to install"
            )
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("KicsScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: KICS walks the target itself and picks the files it understands."""
        return None

    def _assets_dir(self) -> Path:
        """The directory holding ``queries`` and ``libraries``, next to the binary.

        Raises:
            ScannerError: KICS is not found, or none of ``ASSET_DIR_CANDIDATES``
                holds both directories.
        """
        found = find_executable(self.command or "kics")
        if not found:
            raise ScannerError("kics executable not found in PATH")
        binary_dir = Path(os.path.realpath(found)).parent
        tried: List[str] = []
        for candidate in ASSET_DIR_CANDIDATES:
            assets = Path(os.path.normpath(binary_dir / candidate))
            tried.append(assets.as_posix())
            if (assets / "queries").is_dir() and (assets / "libraries").is_dir():
                return assets
        raise ScannerError(
            "kics was found but its queries were not: the release archive holds only "
            "the binary, and ASH looks for the pinned assets directory (with "
            f"queries and libraries in it) at {', '.join(tried)}. Install both with "
            "`ash dependencies install --tool kics`."
        )

    def _empty_config(self, output_dir: Path) -> Path:
        """An empty KICS config written outside the tree, passed with ``--config``.

        KICS loads a ``kics.config`` from the scanned directory when it is given
        none, and that file can drop paths and queries. ``{}`` is valid and
        overrides it (measured).
        """
        stub = output_dir / "kics-no-config.json"
        stub.parent.mkdir(parents=True, exist_ok=True)
        with open_for_write(stub) as handle:
            handle.write("{}\n")
        return Path(os.path.abspath(stub))

    def _build_arguments(
        self, target: Path, output_dir: Path, config_stub: Path, assets: Path
    ) -> List[str]:
        """The full KICS argv for one target. Every option is one token."""
        args: List[str] = [
            self.command or "kics",
            *self.subcommands,
            "--no-progress",
            "--no-color",
            "--silent",
            "--disable-secrets",
            "--ignore-on-exit=results",
            "--exclude-gitignore",
            "--report-formats=json,sarif",
            f"--output-name={REPORT_NAME}",
            f"--output-path={output_dir.as_posix()}",
            f"--config={config_stub.as_posix()}",
            f"--queries-path={(assets / 'queries').as_posix()}",
            f"--libraries-path={(assets / 'libraries').as_posix()}",
        ]
        target_abs = Path(os.path.abspath(target))
        for relative in self._ash_output_dirs_inside(target):
            excluded = Path(os.path.normpath(target_abs / relative))
            # A comma would split the value into two paths.
            if "," not in excluded.as_posix():
                args.append(f"--exclude-paths={excluded.as_posix()}")
        args.append(f"--path={self._scan_path(target)}")
        return args

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the subprocess's working directory), else absolute."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and the SARIF report path for one KICS run.

        ``global_ignore_paths`` is not translated into KICS options: it is applied to
        every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("KicsScanner has no results directory")
        # The base keeps the worst exit code across the source and converted runs.
        self.exit_code = 0
        assets = self._assets_dir()
        # Absolute: the working directory is the source directory.
        output_dir = Path(self.results_dir).absolute().joinpath(target_type)
        output_dir.mkdir(exist_ok=True, parents=True)
        results_file = output_dir / f"{REPORT_NAME}.sarif"
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        (output_dir / f"{REPORT_NAME}.json").unlink(missing_ok=True)
        stub = self._empty_config(output_dir)
        final_args = self._build_arguments(target, output_dir, stub, assets)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run KICS did not finish (any exit but 0)."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"kics exited {self.exit_code}; with --ignore-on-exit=results it "
                "exits 0 when it ran to completion (whatever it found), so this run "
                "failed"
            )
        return super()._read_results_file(results_file)

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where KICS' log is, without quoting it.

        KICS' output can quote the scanned files, so it stays in the log file.
        """
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (kics was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). kics' log is not quoted here; "
            f"see {log_path.as_posix()}"
        )

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep KICS' stderr out of ``self.errors``."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    @staticmethod
    def _output_dir_of(final_args: List[str]) -> Optional[Path]:
        for token in final_args:
            if token.startswith("--output-path="):
                return Path(token.split("=", 1)[1])
        return None

    def _query_severities(self, final_args: List[str]) -> Optional[Dict[str, str]]:
        """``query id -> KICS severity`` from the JSON report, or None."""
        output_dir = self._output_dir_of(final_args)
        reason = None
        if output_dir is None:
            reason = "its report directory is unknown"
        else:
            try:
                raw = read_bytes_at_most(
                    output_dir / f"{REPORT_NAME}.json", _JSON_READ_LIMIT + 1
                )
                if len(raw) > _JSON_READ_LIMIT:
                    raise ValueError("the JSON report is too large")
                document = json.loads(raw.decode("utf-8"))
                if not isinstance(document, dict):
                    raise ValueError("the JSON report is not an object")
                table: Dict[str, str] = {}
                for query in document.get("queries") or []:
                    if not isinstance(query, dict):
                        continue
                    query_id, severity = query.get("query_id"), query.get("severity")
                    if isinstance(query_id, str) and isinstance(severity, str):
                        table[query_id] = severity.upper()
                return table
            except (OSError, ValueError) as exc:
                reason = f"it could not be read ({type(exc).__name__})"
        self._plugin_log(
            f"Could not read KICS' JSON report because {reason}; each result is "
            "rated from its rule's SARIF level, which cannot tell CRITICAL from HIGH, "
            "so the more severe one is used.",
            level=logging.WARNING,
        )
        return None

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Rate every result by its query's KICS severity, level and kind agreeing."""
        severities = self._query_severities(final_args)
        for run in sarif_report.runs or []:
            rule_levels: Dict[str, str] = {}
            driver = run.tool.driver if run.tool else None
            for rule in (driver.rules if driver and driver.rules else []) or []:
                config = rule.defaultConfiguration
                if rule.id and config is not None and config.level is not None:
                    rule_levels[rule.id] = getattr(config.level, "value", config.level)
            for result in run.results or []:
                kics_severity = (severities or {}).get(result.ruleId or "")
                if kics_severity not in KICS_SEVERITY_MAP:
                    level_name = rule_levels.get(result.ruleId or "", "error")
                    kics_severity = RULE_LEVEL_FALLBACK.get(level_name, "CRITICAL")
                ash_severity, level, kind = KICS_SEVERITY_MAP[kics_severity]
                result.level = level
                result.kind = kind
                tags = list(getattr(result.properties, "tags", None) or [])
                if "iac" not in tags:
                    tags.append("iac")
                if result.properties is None:
                    result.properties = PropertyBag(tags=tags)
                else:
                    result.properties.tags = tags
                setattr(result.properties, "issue_severity", ash_severity)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "kics")
        if not found:
            ASH_LOGGER.warning(
                "kics executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_kics_plugins\"]' --tool kics`."
            )
        return found is not None


__all__ = [
    "ASSET_DIR_CANDIDATES",
    "KICS_SEVERITY_MAP",
    "KicsScanner",
    "KicsScannerConfig",
    "KicsScannerConfigOptions",
    "REPORT_NAME",
    "RULE_LEVEL_FALLBACK",
]
