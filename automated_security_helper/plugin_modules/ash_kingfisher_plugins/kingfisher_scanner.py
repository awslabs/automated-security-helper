# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Kingfisher: MongoDB's secret scanner, as a community scanner plugin.

What it runs
------------
``kingfisher scan`` over the scan target: the files as they are on disk. Kingfisher
can also scan git history, remote platforms and archives; ASH asks for none of that
(``--git-history=none``), so it reads what ASH's builtin ``gitleaks`` and
detect-secrets scanners read. Kingfisher is Apache-2.0 licensed and maintained by
MongoDB (https://github.com/mongodb/kingfisher).

Kingfisher is a community plugin: it is loaded only when ``ash_kingfisher_plugins``
is listed in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a
scan that does not list the module is unchanged by its existence. It runs beside the
builtin secret scanners, not instead of them, so a secret more than one finds is
reported by each.

Scan flow
---------
Template flow: ``_execute_scan`` builds the argv and the base ``scan()`` runs it. One
invocation writes one SARIF file with ``--output``, so no second pass or own ``scan()``
is needed.

Invocation
----------
Every run carries these flags. Each is from Kingfisher's own documentation or source
(``src/cli/commands/scan.rs``, ``src/cli/global.rs``, ``docs/USAGE.md``, read for
2.19.1); the ones marked "measured" were also run against 2.19.1.

* ``--no-validate``: Kingfisher validates every finding it can against the provider's
  live API by default, which sends the candidate credential to a third party. ASH
  passes ``--no-validate`` unless the operator turns on
  ``options.validate_credentials`` (see "Validation").
* ``--no-update-check``: Kingfisher otherwise checks for a newer release itself.
* ``--quiet``: no progress output.
* ``--redact``: report values are hashed ("Redact findings values using a secure
  hash"). Measured: the SARIF snippet reads ``[REDACTED:<hash>]``.
  ``_post_process_sarif`` also overwrites any snippet that is not in that form.
* ``--no-ignore``: "Disable inline ignore directives entirely". Without it a
  comment in the scanned file can hide a finding from ASH, which is where
  suppressions are reported and counted.
* ``--git-history=none``: scan the working tree only.
* ``--format=sarif`` and ``--output=<file>``: SARIF 2.1.0 written to a file. The
  format is marked "experimental" in Kingfisher's own help text.

None of the config flags is passed: Kingfisher does not auto-discover
``kingfisher.yaml`` (its docs say it is "never auto-discovered"), so the scanned tree
cannot supply one. No baseline flag is passed either.

Every option is one ``--flag=value`` token and the scan path follows ``--``, so no path
is read as a flag. The subprocess working directory is the source directory, so
reported paths are source-relative. Kingfisher writes them with a leading ``./``,
which ``_post_process_sarif`` removes.

Severity
--------
Every finding is CRITICAL, SARIF level ``error``, kind ``fail``, as every finding of
ASH's other secret scanners is: each rule says "a credential of this kind is present".
Kingfisher's own SARIF level follows its confidence setting (low is ``note``, medium
``warning``, high ``error``); that is a statement about how sure the rule is, not
about the harm of an exposed credential, and ASH does not let it lower the rating.
``issue_severity`` and the SARIF level agree on every result.

Exit status and output
----------------------
Kingfisher exits 0 when it finds nothing, 200 when it finds anything and 205 when it
finds a credential that live validation confirmed (``determine_exit_code`` in
``src/main.rs``); 3 means it was given nothing to scan. So 0, 200 and 205 are success
and every other code fails the scan, even with a report on disk. A report left by an
earlier run is removed before each run.

Offline
-------
With ``--no-validate`` and ``--no-update-check`` Kingfisher's rules are compiled into
the binary and a local scan sends nothing anywhere ("Local checkout scans remain
offline" is the documented behaviour for the repository-ID lookup; no rule download is
documented). With ``validate_credentials`` on, validation sends the candidate
credentials to each provider, so it is never combined with an offline run.

Validation
----------
``options.validate_credentials`` is off, and only the operator can turn it on: the
way ``snyk-code`` keeps its network-using options out of the scanned tree's reach,
through ``SET_BY_THE_OPERATOR``. The strict sandbox below grants no network, so
validation requests cannot succeed inside it; the option is meant for runs outside the
scanner sandbox.

Sandbox
-------
The strict default (``SandboxRequirements()``): no network, baseline environment only.
Kingfisher reads no environment variable of its own for the flags ASH passes.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import Field, PrivateAttr, model_validator

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
from automated_security_helper.config.confinement_remedy import (
    KEEP_A_SETTING,
    SET_BY_THE_OPERATOR,
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
from automated_security_helper.utils.config_trust import set_by_operator
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import downloadable_tools

#: What a snippet reads after ``--redact``: ``[REDACTED:<hash>]``. Measured on 2.19.1.
_REDACTED_SNIPPET = re.compile(r"^\[REDACTED:[0-9A-Za-z]+\]$")

#: What a snippet reads when it is not in the form above.
REDACTED = "REDACTED"

#: Exit codes that mean Kingfisher ran to completion: nothing found, something found,
#: a live-validated credential found. See "Exit status and output" above.
NOTHING_FOUND_EXIT_CODE = 0
FINDINGS_EXIT_CODE = 200
VALIDATED_EXIT_CODE = 205

#: The option path ``set_by_operator`` is asked about.
_VALIDATE_OPTION_PATH = "scanners.kingfisher.options.validate_credentials"


class KingfisherScannerConfigOptions(ScannerOptionsBase):
    validate_credentials: Annotated[
        bool,
        Field(
            description=(
                "Let Kingfisher validate each finding against the provider's live "
                "API. Off by default: ASH runs `kingfisher scan --no-validate`, "
                "because validation sends the candidate credential to a third party. "
                "The scanner sandbox grants no network, so validation only works "
                f"outside it. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning."
            ),
        ),
    ] = False


class KingfisherScannerConfig(ScannerPluginConfigBase):
    name: Literal["kingfisher"] = "kingfisher"
    enabled: bool = True
    options: Annotated[
        KingfisherScannerConfigOptions,
        Field(description="Configure the kingfisher scanner"),
    ] = KingfisherScannerConfigOptions()


@ash_scanner_plugin
class KingfisherScanner(ScannerPluginBase[KingfisherScannerConfig]):
    """Secret detection over the scan target's files using Kingfisher."""

    #: Not Python-only: Kingfisher is a native binary, installed from its pinned
    #: release asset, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    # With --no-validate and --no-update-check a local scan makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = {
        NOTHING_FOUND_EXIT_CODE,
        FINDINGS_EXIT_CODE,
        VALIDATED_EXIT_CODE,
    }
    # The strict default; see "Sandbox" in the module docstring. Live validation
    # would need network, which waits for a sandbox grant gate.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    # Kingfisher's log can name files and rules from the scanned tree, and the
    # scanner executor copies errors into the scan's results: the base class keeps
    # the stream out of both and out of the failure text. It stays in the log file.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "kingfisher"

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name Kingfisher's own SARIF (fixture
    #: tests/test_data/scanners/kingfisher/captured/positive.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(constant) level error plus properties "
            '"issue_severity" CRITICAL, both set by _post_process_sarif; the '
            'native result "level" follows the confidence setting and is '
            "overwritten (see the module docstring, Severity)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startLine / region.endLine",
        ),
        column=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.startColumn / region.endColumn",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file location, not a deployable "
            "resource; the SARIF carries a rule id and a region only",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file location, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="Kingfisher rules carry no CWE taxonomy in the SARIF",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "partialFingerprints.fingerprint"',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason='the SARIF rules carry an empty "help" text; no remediation '
            "guidance is emitted",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text ([REDACTED:<hash>] under --redact), "
            "forced to REDACTED by _post_process_sarif when it is not in that form",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry descriptions only; no reference URLs "
            "per rule or result",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="the native SARIF carries no per-result or per-rule tags; "
            "the adapter appends secret and security afterwards",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="kingfisher",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "kingfisher_scanner.py offline_strategy, sandbox_requirements; "
                    "module header (Offline): ASH passes --no-validate and "
                    "--no-update-check, and the rules are compiled into the binary"
                ),
                unconfirmed=(
                    "options.validate_credentials, operator-only, sends candidate "
                    "credentials to each provider; the strict sandbox grants no "
                    "network, so it only works outside the sandbox"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="--format=sarif is marked experimental in Kingfisher's own help",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SECRETS_CONTENTS,),
                tool_type=ScannerToolType.SECRETS,
                selection="`kingfisher scan --git-history=none` over the target; "
                "contents, not history (module header)",
                covers_note=(
                    "the community scanners declare no covers display string; no "
                    "scanner claims git-history secrets (UNCLAIMED_TARGET_KINDS)"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="utils/tool_downloads has no kingfisher pin, so ASH provisions "
                "nothing; the operator puts the binary on PATH",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DEGRADED,
                note="every finding is CRITICAL, as for ASH's other secret scanners; "
                "Kingfisher's own level follows its confidence setting and is "
                "overwritten",
                dropped_native='result "level" (low is note, medium warning, '
                "high error)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="Kingfisher's inline ignore directives in scanned "
                        "files",
                        cite="kingfisher_scanner.py module header (Invocation): "
                        "ASH passes --no-ignore",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="the capture carries partialFingerprints.fingerprint and ASH "
                "keys identity by it; whether it stays stable across an edit above "
                "the finding is not measured",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="options.validate_credentials only, operator-set; "
                "no config, rules or baseline flag is passed and the tree cannot "
                "supply a kingfisher.yaml",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 200, 205),
                semantics="0 nothing found, 200 findings, 205 a live-validated "
                "credential; 3 means nothing to scan and fails the scan",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_kingfisher_plugins in ash_plugin_modules",
                    "options.validate_credentials",
                ),
                upstream_license=(
                    "Apache-2.0 (source: mongodb/kingfisher LICENSE at tag v2.19.1)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no git repository is required and no history is read",
            ),
        )
    )

    # Whether the tree-set validate_credentials refusal was already logged.
    _validate_refusal_logged: bool = PrivateAttr(default=False)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = KingfisherScannerConfig()
        self.command = "kingfisher"
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SECRETS
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token Kingfisher would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "KingfisherScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``.

        Until that table has a ``kingfisher`` entry there is nothing to install from;
        the scanner still loads, finds the binary on PATH if one is there, and says
        so when it is missing.
        """
        try:
            self.custom_install_commands.update(
                pinned_tool_install_commands("kingfisher")
            )
        except ToolNotProvisionableError:
            ASH_LOGGER.debug(
                "kingfisher has no pinned release table; install it yourself and "
                "put it on PATH"
            )
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> KingfisherScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, KingfisherScannerConfigOptions):
            return options
        return KingfisherScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("KingfisherScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before Kingfisher runs whether it reads any file.

        Kingfisher is handed the whole target and walks it itself, so ASH makes no
        selection of its own that could come up empty.
        """
        return None

    def _validate_credentials(self) -> bool:
        """Whether Kingfisher may validate findings against provider APIs."""
        if not self._options().validate_credentials:
            return False
        config = self.context.config if self.context is not None else None
        if set_by_operator(config, _VALIDATE_OPTION_PATH, True):
            return True
        if not self._validate_refusal_logged:
            self._validate_refusal_logged = True
            self._plugin_log(
                f"{_VALIDATE_OPTION_PATH} is true in a config inside a git checkout "
                "or the scanned directory, or from an MCP client, so it is ignored: "
                "Kingfisher runs with --no-validate and sends no credential "
                f"anywhere. {KEEP_A_SETTING}",
                level=logging.WARNING,
            )
        return False

    def _scan_path(self, target: Path) -> str:
        """The path Kingfisher is given: ``.`` for the source, absolute otherwise.

        The source target as "." from the source directory (the subprocess's working
        directory), so reported paths are source-relative.
        """
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full Kingfisher argv for one target.

        Every option is one ``--flag=value`` token and the scan path follows ``--``.
        """
        args: List[str] = [
            self.command or "kingfisher",
            *self.subcommands,
            "--no-update-check",
            "--quiet",
            "--redact",
            "--no-ignore",
            "--git-history=none",
            "--format=sarif",
            f"--output={results_file.as_posix()}",
        ]
        if not self._validate_credentials():
            args.insert(len(self.subcommands) + 1, "--no-validate")
        args.extend(["--", self._scan_path(target)])
        return args

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Kingfisher run.

        ``global_ignore_paths`` is not translated into Kingfisher flags: it is applied
        to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("KingfisherScanner has no results directory")
        # The executor runs this instance over the source and then the converted
        # target and keeps the worst exit code; start each run from zero.
        self.exit_code = 0
        # Absolute: the run's working directory is the source directory, and a
        # relative output directory would have the report written there.
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "kingfisher.sarif")
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
        """Refuse the report of a run Kingfisher did not finish."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"kingfisher exited {self.exit_code}; it exits "
                f"{NOTHING_FOUND_EXIT_CODE} when it finds nothing, "
                f"{FINDINGS_EXIT_CODE} when it finds secrets and "
                f"{VALIDATED_EXIT_CODE} when it finds validated ones, so this run "
                "failed"
            )
        return super()._read_results_file(results_file)

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _committed_file_test(self) -> Callable[[Path], bool]:
        """A test, of a path, for a file the repository committed under ASH's output."""
        committed: Optional[Set[Path]] = None

        def is_committed(path: Path) -> bool:
            nonlocal committed
            if committed is None:
                committed = committed_output_files(self.context)
            try:
                return path.resolve() in committed
            except (OSError, RuntimeError, ValueError):
                return False

        return is_committed

    def _output_dirs_inside_target(self, target: Path) -> List[Path]:
        """ASH's output directories inside ``target``, relative to it."""
        found: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            found.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in found:
                found.append(relative)
        return found

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove the results located under ASH's output directory inside ``target``.

        Kingfisher is given the whole target, so when the output directory is inside
        it (the default ``.ash/ash_output``) it reads ASH's own files. A result in a
        file the repository committed there is kept.
        """
        if self.context is None:
            return
        outputs_inside = self._output_dirs_inside_target(target)
        if not outputs_inside:
            return
        target_abs = Path(target).absolute()
        output_roots = [Path(os.path.normpath(target_abs / o)) for o in outputs_inside]
        committed = self._committed_file_test()

        def under_output_dir(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if not uri:
                    continue
                if os.sep == "\\":
                    uri = uri.replace("\\", "/")
                path = Path(os.path.normpath(target_abs / uri))
                if any(path.is_relative_to(root) for root in output_roots) and (
                    not committed(path)
                ):
                    return True
            return False

        dropped = 0
        for run in sarif_report.runs or []:
            if not run.results:
                continue
            kept = [result for result in run.results if not under_output_dir(result)]
            dropped += len(run.results) - len(kept)
            run.results = kept
        if dropped:
            self._plugin_log(
                f"Dropped {dropped} finding(s) under ASH's output directory: copies "
                "of the files ASH converted, or files ASH wrote.",
                level=logging.DEBUG,
            )

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, rate every result, keep snippets redacted."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            # See "Severity" in the module docstring.
            result.level = Level.error
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("secret", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", "CRITICAL")  # noqa: B010

            for location in result.locations or []:
                physical = location.physicalLocation
                if physical is None:
                    continue
                artifact = physical.root.artifactLocation
                if artifact is not None and artifact.uri:
                    # Kingfisher writes "./creds.txt" for a "." scan path.
                    artifact.uri = artifact.uri.removeprefix("./")
                region = physical.root.region
                snippet = region.snippet if region else None
                if (
                    snippet is not None
                    and snippet.text is not None
                    and not _REDACTED_SNIPPET.match(snippet.text)
                ):
                    snippet.text = REDACTED

        for run in sarif_report.runs or []:
            # Kingfisher's run properties hold a repository audit with the absolute
            # path of the scanned directory and timings; nothing in ASH reads it.
            run.properties = None
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "kingfisher")
        if not found:
            # ASH installs only tools with a pinned release table. Until
            # utils/tool_downloads has a kingfisher entry, the operator installs it.
            hint = (
                "Install it from https://github.com/mongodb/kingfisher and put it "
                "on PATH (ASH has no pinned release for it)."
            )
            if "kingfisher" in downloadable_tools():
                hint = (
                    "Install it with `ash dependencies install --config-overrides "
                    "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                    "ash_kingfisher_plugins\"]' --tool kingfisher`."
                )
            ASH_LOGGER.warning(f"kingfisher executable not found in PATH. {hint}")
        return found is not None


__all__ = [
    "FINDINGS_EXIT_CODE",
    "KingfisherScanner",
    "KingfisherScannerConfig",
    "KingfisherScannerConfigOptions",
    "NOTHING_FOUND_EXIT_CODE",
    "VALIDATED_EXIT_CODE",
]
