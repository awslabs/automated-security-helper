# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TruffleHog: a secret scanner that can verify what it finds, as an alpha plugin.

What it runs
------------
``trufflehog filesystem`` over the scan target: the files as they are on disk, not
git history, which is what ASH's gitleaks and detect-secrets scanners read as well.
TruffleHog matches a credential with a detector written for its provider, and can
then ask the provider whether the credential is live ("verification").

TruffleHog is an alpha plugin: it is loaded only when ``ash_trufflehog_plugins``
is listed in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a
scan that does not list the module is unchanged by its existence. It runs beside the
builtin secret scanners, not instead of them, so a secret two of them find is
reported by each.

ASH does not install TruffleHog and the container image does not include it: it is
AGPL-3.0 licensed, and ASH runs whichever ``trufflehog`` is on ``PATH`` as a
separate process. Everything below was measured on the 3.100.0 release binary.

Verification is off unless the operator turns it on
---------------------------------------------------
Verifying a credential sends it to its provider's API, and for some detectors to a
host the scanned file names (a database URL, a self-hosted service). So ASH passes
``--no-verification`` unless ``options.verify`` is true and the operator set it
(``--config-overrides`` or a config file outside every git checkout and the scanned
directory, ``utils/config_trust.py``). Set by a config inside a git checkout or the
scanned directory, or by an MCP client, it is ignored with a warning. ASH's own
offline mode and the scanner's ``options.offline`` each override it.

With verification on, ``options.results`` chooses which results TruffleHog reports
(``--results``): ``verified`` (the provider confirmed it), ``unknown`` (the check
failed, so it may be live) and ``unverified`` (the provider rejected it, or the
detector has no check). The default is ``verified,unknown``, and another value is
used only when the operator set it: narrowed by the scanned tree it would hide
findings. Without verification every detection is reported, since none can be told
from another.

Invocation
----------
Every run carries these flags, and none of them is configurable.

* ``--sarif``: TruffleHog writes SARIF to stdout, which ASH writes to
  ``TruffleHogScanner.stdout.log`` and reads from there. The SARIF holds the
  detector, the file and the line, and never the secret: unlike the ``--json``
  output, whose ``Raw``, ``RawV2`` and ``SecretParts`` fields carry it, so ASH
  never asks for that format and no file it leaves holds the value.
* ``--no-update``: no check for a newer release, and no self-update.
* ``--no-color``: the log goes to a file nobody reads in a terminal.
* ``--fail-on-scan-errors``: exit 1 when the scan itself fails. A file TruffleHog
  cannot read is only logged ("error scanning file") and the exit status stays 0
  (measured), so ASH counts those log lines and warns with the count.
* ``--no-ignore-tag``: a ``trufflehog:ignore`` comment on a line drops its finding
  before ASH sees it, so it would be neither reported nor counted as suppressed.
  ``options.honor_inline_ignores: true`` leaves the flag out, honored only when the
  operator set it.
* ``--exclude-paths=<file ASH writes>``: one pattern, any ``.git`` directory. Git's
  object store is not a checked-out file, and reading it reports a secret again
  for each object that holds it.

``--config`` is never passed, so no custom detector or verification endpoint is
loaded, and TruffleHog reads no configuration from the scanned tree. Its
``filesystem`` command reads no environment variable. Symbolic links are not
followed (``--max-symlink-depth`` defaults to 0).

The scan path is ``.`` with the working directory at the source directory, so
reported paths are source-relative (``src/settings.py``), and an absolute path for
the converted target.

Severity
--------
TruffleHog's SARIF has two levels. ``error`` is a credential its provider confirmed
live: CRITICAL. ``warning`` is every other detection, verified or not: HIGH. Each
result carries ``properties.verification``, ``verified`` or ``not verified``.

Duplicates
----------
The generic ``URI`` detector matches a credential by its shape in a URL, so it
often reports the line a provider's detector already reports. That result is
dropped when a provider detector reports the same file and line at the same or a
stronger level. Two provider detectors on one line are both kept: they may be two
secrets.

Exit status and output
----------------------
0 is success, with or without findings; ASH never passes ``--fail``. TruffleHog's
stderr is not copied into the scan's errors, and the scan failure message names the
log instead of quoting it: with verification on, the log can hold what a provider
answered.

Offline
-------
The detectors are compiled into the binary. Offline, nothing is verified.

Sandbox
-------
The strict default: no network. Verification needs one, an option-derived grant,
so under ``--sandbox`` TruffleHog gets a network only when
``sandbox.network_scanners`` lists it; without it each check fails and the
detection is still reported, as an ``unknown`` result (measured with every proxy
variable pointing at a closed port).
"""

from __future__ import annotations

import logging
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

from pydantic import Field, PrivateAttr, field_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_base import read_log_bounded
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
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The values ``trufflehog --results`` takes that ASH offers. ``filtered_unverified``
#: is left out: it brings back the results TruffleHog's own filter judged noise.
RESULT_KINDS = ("verified", "unknown", "unverified")

#: What ``options.results`` is when unset: the credentials a provider confirmed, and
#: the ones whose check failed, which may be live.
DEFAULT_RESULTS = "verified,unknown"

#: The one pattern in the ``--exclude-paths`` file: any ``.git`` directory, with
#: either path separator.
GIT_DIR_PATTERN = r"(^|[/\\])\.git([/\\]|$)"

#: Detectors that match a credential by its shape in a URL, not by provider. See
#: "Duplicates" in the module docstring.
GENERIC_DETECTORS = frozenset({"URI"})

#: What TruffleHog logs for a file it could not read. The scan goes on and exits 0.
FILE_ERROR_LOG = "error scanning file"

#: The most of TruffleHog's log ASH reads to count ``FILE_ERROR_LOG`` lines.
_LOG_READ_LIMIT = 16 * 1024 * 1024

_LEVEL_RANK = {Level.error: 1}


def _rank(level: Optional[Level]) -> int:
    """How strongly a result's level ranks; an unset level ranks lowest."""
    return 0 if level is None else _LEVEL_RANK.get(level, 0)


class TruffleHogScannerConfigOptions(ScannerOptionsBase):
    verify: Annotated[
        bool,
        Field(
            description=(
                "Let TruffleHog verify each credential it finds. Off by default: "
                "ASH runs `trufflehog --no-verification` and nothing leaves the "
                "host. When true, TruffleHog sends each credential it finds to its "
                "provider's API, or to a host the scanned file names, to learn "
                "whether it is live, and a confirmed one is reported as CRITICAL. "
                f"{SET_BY_THE_OPERATOR} It is ignored, with a warning, when ASH "
                "runs in offline mode or this scanner's own `offline` option is "
                "true."
            ),
        ),
    ] = False
    results: Annotated[
        str,
        Field(
            description=(
                "Which results TruffleHog reports when `verify` is on, as "
                "`trufflehog --results` takes them: a comma-separated list of "
                "`verified` (the provider confirmed the credential), `unknown` "
                "(the check failed, so it may be live) and `unverified` (the "
                "provider rejected it, or the detector has no check). Without "
                "`verify` every detection is reported whatever this is set to. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with a "
                "warning and the default applies."
            ),
        ),
    ] = DEFAULT_RESULTS
    honor_inline_ignores: Annotated[
        bool,
        Field(
            description=(
                "Honor inline `trufflehog:ignore` comments. Off by default: ASH "
                "runs `trufflehog --no-ignore-tag`, so every finding reaches ASH, "
                "where suppressions are reported and counted. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with a "
                "warning."
            ),
        ),
    ] = False

    @field_validator("results")
    @classmethod
    def _valid_results(cls, value: str) -> str:
        kinds = [part.strip() for part in value.split(",") if part.strip()]
        unknown = [kind for kind in kinds if kind not in RESULT_KINDS]
        if not kinds or unknown:
            raise ValueError(
                "results is a comma-separated list of "
                f"{', '.join(RESULT_KINDS)}; got {value!r}"
            )
        # In TruffleHog's own order, each once, so one setting has one spelling.
        return ",".join(kind for kind in RESULT_KINDS if kind in kinds)


class TruffleHogScannerConfig(ScannerPluginConfigBase):
    name: Literal["trufflehog"] = "trufflehog"
    enabled: bool = True
    options: Annotated[
        TruffleHogScannerConfigOptions,
        Field(description="Configure the trufflehog scanner"),
    ] = TruffleHogScannerConfigOptions()


@ash_scanner_plugin
class TruffleHogScanner(ScannerPluginBase[TruffleHogScannerConfig]):
    """Secret detection over the scan target's files using TruffleHog."""

    #: Not Python-only: TruffleHog is a native binary, so a Python-only scan does
    #: not run it.
    python_only: ClassVar[bool | None] = False

    # The detectors are compiled into the binary; offline, nothing is verified.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    #: Without --fail, which ASH never passes, TruffleHog exits 0 with or without
    #: findings, and 1 when the scan failed.
    success_exit_codes: ClassVar[Set[int]] = {0}

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name TruffleHog's own SARIF (fixtures
    #: tests/test_data/scanners/trufflehog/captured/positive.sarif and
    #: negative.sarif, TruffleHog 3.100.0, four results over three files). A cell
    #: the capture does not settle is UNCONFIRMED with the run that would settle
    #: it. ``--no-verification`` is the default argv, so no capture holds a
    #: verified (``level: error``) result.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (the detector name, for example Github or URI)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (warning in every result of the capture; '
            "error is a provider-confirmed credential per the module header), rated "
            'by _post_process_sarif into properties "issue_severity" (error to '
            "CRITICAL, anything else to HIGH)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.region.startLine "
            "(no endLine in the capture)",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the regions of the capture carry startLine only (4 of 4 "
            "results); TruffleHog's SARIF holds no column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text" (names the detector and the '
            "verification state, never the secret)",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="secret findings name a file location, not a deployable "
            "resource; the SARIF carries a detector, a region and a fingerprint only",
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
            reason="the rules of the capture carry id, name and shortDescription "
            "only; no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "partialFingerprints" '
            '("trufflehogFingerprint/v1", one value per result; 4 distinct '
            "values over 4 results in the capture)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the rules of the capture carry id, name and shortDescription only",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="the regions of the capture carry no snippet, and ASH never asks "
            "for the --json output whose Raw fields hold the secret (module header)",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the rules of the capture carry id, name and shortDescription "
            "only; no reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "tags" (absent natively); the adapter '
            "appends secret and security",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" and "verification" '
            "written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="trufflehog",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.ISSUER_VERIFICATION,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.DEGRADED,
                offline_reason=(
                    "verification is off by default; with options.verify on, an "
                    "offline run falls back to --no-verification and the detections "
                    "are all reported unverified, none dropped"
                ),
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                sandbox_tension=(
                    "options.verify (operator-only, off by default) sends each "
                    "credential found to its provider, or to a host the scanned file "
                    "names, but the sandbox declaration grants no network, so under "
                    "--sandbox a verifying run gets one only when "
                    "sandbox.network_scanners lists trufflehog; without it each check "
                    "fails and the detection is reported as unknown"
                ),
                source=(
                    "trufflehog_scanner.py offline_strategy, sandbox_requirements and "
                    "_verify; module header (Verification is off unless the operator "
                    "turns it on; Sandbox); the default argv passes --no-verification "
                    "and --no-update"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="the SARIF goes to stdout and ASH writes it to "
                "TruffleHogScanner.stdout.log; the tool has no report-file option",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SECRETS_CONTENTS,),
                tool_type=ScannerToolType.SECRETS,
                selection="`trufflehog filesystem` over the target; the files on disk, "
                "not history, and not .git directories (--exclude-paths; module header)",
                covers_note=(
                    "the alpha scanners declare no covers display string; no "
                    "scanner claims git-history secrets (UNCLAIMED_TARGET_KINDS)"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("trufflehog",),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="the user's installed TruffleHog, absent from TOOL_VERSIONS, so "
                "ASH provisions no platform (module header: ASH does not install it); "
                "the committed capture is from the darwin/arm64 release asset, and "
                "which other platforms the tool runs on is the user's install",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="the native level has two values; ASH rates a provider-confirmed "
                "credential (level error) CRITICAL and every other detection HIGH",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="trufflehog:ignore comments; options.honor_inline_ignores "
                        "turns them back on when the operator sets it",
                        cite="trufflehog_scanner.py module header (Invocation, "
                        "--no-ignore-tag) and _honor_inline_ignores; the capture's "
                        "src/services/settings.py result is reported despite its "
                        "ignore comment (captured/README.md)",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.TOOL_DEFAULT_FILTER,
                        writer=opsf.SilencingWriter.TOOL_DEFAULT,
                        honored=opsf.Honored.YES,
                        surface="--results=verified,unknown, passed only when "
                        "options.verify is on, drops the results a provider "
                        "rejected; TruffleHog's own filtered_unverified class is "
                        "never requested",
                        cite="trufflehog_scanner.py module header (Verification is "
                        "off unless the operator turns it on), RESULT_KINDS and "
                        "DEFAULT_RESULTS",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="every result of the capture carries partialFingerprints "
                "trufflehogFingerprint/v1; the capture README says it is a hash over "
                "the detector, path, line and a hash of the secret, so it may move "
                "with an edit above the finding, and no capture moves a line; a "
                "before and after run over one edit settles it",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed options (verify, results, honor_inline_ignores); "
                "--config is never passed, so no custom detector or verification "
                "endpoint is loaded and no configuration is read from the scanned tree",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="0 with or without findings, because ASH never passes "
                "--fail; 1 when the scan itself failed (--fail-on-scan-errors); a "
                "file it cannot read is only logged and the exit stays 0",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_trufflehog_plugins in ash_plugin_modules",
                    "options.verify",
                    "options.results",
                    "options.honor_inline_ignores",
                ),
                upstream_license=opsf.LICENSE_NOT_READ,
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no git repository is required and no history is read",
            ),
        )
    )

    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: TruffleHog's stderr can hold a provider's answer about a credential, so the
    #: failure text and ``self.errors`` do not quote it; the log file keeps it.
    quote_tool_stderr: ClassVar[bool] = False

    # Whether the offline note was already logged. The tree-set option refusals are
    # logged once by the base class's ``_operator_gated``.
    _verify_offline_logged: bool = PrivateAttr(default=False)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = TruffleHogScannerConfig()
        self.command = "trufflehog"
        self.subcommands = ["filesystem"]
        self.tool_type = ScannerToolType.SECRETS
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token TruffleHog would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> TruffleHogScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, TruffleHogScannerConfigOptions):
            return options
        return TruffleHogScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("TruffleHogScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before TruffleHog runs whether it reads any file.

        TruffleHog is handed the whole target and walks it itself. Any file it
        reads can hold a secret, so ASH makes no selection of its own that could
        come up empty. None means "cannot tell".
        """
        return None

    def _verify(self) -> bool:
        """Whether TruffleHog may send what it finds to be verified."""
        if not self._options().verify:
            return False
        # Verification sends each credential found off the host, so only the
        # operator can turn it on.
        if not self._operator_gated(
            "scanners.trufflehog.options.verify",
            True,
            False,
            "scanners.trufflehog.options.verify is true in a config inside "
            "a git checkout or the scanned directory, or from an MCP "
            "client, so it is ignored: TruffleHog runs with "
            f"--no-verification and sends nothing. {KEEP_A_SETTING}",
        ):
            return False
        # ASH's own offline mode, or this scanner's options.offline (read by the
        # base class as every scanner's is): either keeps TruffleHog offline.
        if self._scanner_offline():
            if not self._verify_offline_logged:
                self._verify_offline_logged = True
                self._plugin_log(
                    "scanners.trufflehog.options.verify is true but ASH, or this "
                    "scanner's own offline option, is offline; running TruffleHog "
                    "with --no-verification.",
                    level=logging.WARNING,
                )
            return False
        return True

    def _results(self) -> str:
        """The ``--results`` value for a verifying run: the operator's, or the default.

        Narrowed to ``verified``, the results a provider did not confirm are left
        out before ASH sees them, so the scanned tree does not choose it.
        """
        wanted = self._options().results
        if wanted == DEFAULT_RESULTS:
            return wanted
        return self._operator_gated(
            "scanners.trufflehog.options.results",
            wanted,
            DEFAULT_RESULTS,
            f"scanners.trufflehog.options.results is {wanted!r} in a config "
            "inside a git checkout or the scanned directory, or from an MCP "
            f"client, so it is ignored: TruffleHog reports {DEFAULT_RESULTS}. "
            f"{KEEP_A_SETTING}",
        )

    def _honor_inline_ignores(self) -> bool:
        """Whether TruffleHog may apply ``trufflehog:ignore`` comments in the tree."""
        if not self._options().honor_inline_ignores:
            return False
        return self._operator_gated(
            "scanners.trufflehog.options.honor_inline_ignores",
            True,
            False,
            "scanners.trufflehog.options.honor_inline_ignores is true in a "
            "config inside a git checkout or the scanned directory, or from an "
            "MCP client, so it is ignored: TruffleHog runs with "
            "--no-ignore-tag and ignore comments do not apply; suppress "
            f"findings with ASH suppressions. {KEEP_A_SETTING}",
        )

    def _scan_path(self, target: Path) -> str:
        """The path TruffleHog is given: ``.`` for the source, absolute otherwise.

        The source target as "." from the source directory (the subprocess's working
        directory), so reported paths are source-relative.
        """
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, exclude_file: Path) -> List[str]:
        """The full TruffleHog argv for one target.

        Every option that takes a value is one ``--flag=value`` token and the scan
        path follows ``--``, so no path or option value can be read as a flag.
        """
        args: List[str] = [
            self.command or "trufflehog",
            *self.subcommands,
            "--sarif",
            "--no-update",
            "--no-color",
            "--fail-on-scan-errors",
        ]
        if self._verify():
            args.append(f"--results={self._results()}")
        else:
            args.append("--no-verification")
        if not self._honor_inline_ignores():
            args.append("--no-ignore-tag")
        args.append(f"--exclude-paths={exclude_file.as_posix()}")
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
        """Resolve the argv and results path for one TruffleHog run.

        ``global_ignore_paths`` is not translated into TruffleHog exclusions: it is
        applied to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("TruffleHogScanner has no results directory")
        # ScannerExecutor runs this instance over the source and then the converted
        # target, and the base class keeps the worst exit code across runs. Without
        # this, a source run that failed (1) failed a clean converted run.
        self.exit_code = 0
        # Absolute: TruffleHog runs with its working directory at the source
        # directory, and a library caller's relative output directory would have
        # the exclusion file looked for there.
        run_dir = Path(self.results_dir).absolute().joinpath(target_type)
        run_dir.mkdir(exist_ok=True, parents=True)
        # TruffleHog has no report-file option: the SARIF goes to stdout, which ASH
        # writes to this file.
        results_file = run_dir / f"{self.__class__.__name__}.stdout.log"
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        exclude_file = run_dir / "trufflehog-exclude-paths.txt"
        with open_for_write(exclude_file, encoding="utf-8") as handle:
            handle.write(GIT_DIR_PATTERN + "\n")
        final_args = self._build_arguments(target, exclude_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _run_subprocess(  # type: ignore[override]
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        **kwargs: Any,
    ) -> Dict[str, str]:
        """Run TruffleHog, then warn about the files its log says it could not read."""
        response = super()._run_subprocess(command, results_dir=results_dir, **kwargs)
        if results_dir is not None:
            self._warn_of_unread_files(
                Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
            )
        return response

    def _warn_of_unread_files(self, log_path: Path) -> None:
        """Say how many files TruffleHog logged that it could not read.

        TruffleHog logs each one and still exits 0, so without this a scan that
        skipped files reads as a complete one. The count is given and the log is
        named; its lines, which name the files, are not quoted.
        """
        try:
            # The text is only counted, never shown, so no values are redacted; the
            # reviewed helper owns the bound, the known cut and the edge trim.
            log, _cut = read_log_bounded(log_path, _LOG_READ_LIMIT, ())
        except OSError:
            return
        unread = log.count(FILE_ERROR_LOG)
        if unread:
            self._plugin_log(
                f"TruffleHog could not read {unread} file(s), so they were not "
                f"scanned; see {log_path.as_posix()}",
                level=logging.WARNING,
            )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where TruffleHog's log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (trufflehog was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        if self.scan_could_not_stop is not None:
            return (
                f"{detail} (no exit code: ASH could not stop trufflehog). "
                f"trufflehog's log is not quoted here; see {log_path.as_posix()}"
            )
        verdict = (
            "an accepted exit code for this scanner"
            if self._exit_code_accepted()
            else "not an accepted exit code; success_exit_codes="
            f"{sorted(self.success_exit_codes)}"
        )
        return (
            f"{detail} (exit code {self.exit_code}: {verdict}). trufflehog's log is "
            f"not quoted here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    # The drop of results under ASH's output directory is the base class's
    # ``_drop_results_under_output_dir``, called from ``_post_process_sarif``.

    @staticmethod
    def _where(result: Any) -> Optional[Tuple[str, int]]:
        """The file and line of a result's first location, or None without one."""
        for location in result.locations or []:
            physical = location.physicalLocation
            artifact = physical.root.artifactLocation if physical else None
            region = physical.root.region if physical else None
            if artifact is None or not artifact.uri:
                continue
            return artifact.uri, (region.startLine if region else None) or 0
        return None

    @staticmethod
    def _drop_generic_duplicates(sarif_report: SarifReport) -> None:
        """Drop a generic detector's result a provider detector already reports.

        See "Duplicates" in the module docstring.
        """
        where_of = TruffleHogScanner._where
        for run in sarif_report.runs or []:
            if not run.results:
                continue
            strongest: Dict[Tuple[str, int], int] = {}
            for result in run.results:
                where = where_of(result)
                if where is None or result.ruleId in GENERIC_DETECTORS:
                    continue
                rank = _rank(result.level)
                strongest[where] = max(rank, strongest.get(where, -1))
            run.results = [
                result
                for result in run.results
                if not (
                    result.ruleId in GENERIC_DETECTORS
                    and (where := where_of(result)) is not None
                    and strongest.get(where, -1) >= _rank(result.level)
                )
            ]

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, then drop generic duplicates and rate every result."""
        self._drop_results_under_output_dir(sarif_report, target)
        return self.normalize_results(sarif_report)

    @staticmethod
    def normalize_results(sarif_report: SarifReport) -> SarifReport:
        """Drop generic duplicates and rate every result, in place.

        The part of the post-processing that needs no scan context, so the
        conformance transcripts can replay it on a captured report.
        """
        TruffleHogScanner._drop_generic_duplicates(sarif_report)
        for result in sarif_report.get_all_results():
            # See "Severity" in the module docstring.
            verified = result.level == Level.error
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("secret", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(  # noqa: B010
                result.properties, "issue_severity", "CRITICAL" if verified else "HIGH"
            )
            setattr(  # noqa: B010
                result.properties,
                "verification",
                "verified" if verified else "not verified",
            )
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "trufflehog")
        if not found:
            ASH_LOGGER.warning(
                "trufflehog executable not found in PATH. ASH does not install "
                "it: install TruffleHog 3.100.0 or later from "
                "https://github.com/trufflesecurity/trufflehog/releases."
            )
        return found is not None


__all__ = [
    "DEFAULT_RESULTS",
    "GENERIC_DETECTORS",
    "GIT_DIR_PATTERN",
    "RESULT_KINDS",
    "TruffleHogScanner",
    "TruffleHogScannerConfig",
    "TruffleHogScannerConfigOptions",
]
