"""Module containing the Opengrep security scanner implementation.

The bulk of the logic (arg-building, offline cache, SARIF post-processing)
lives in :mod:`_grep_scanner_base`. This module only customises:

- the binary command (`opengrep`) and its custom URL-based install commands
- version-gated `--metrics` (deprecated in opengrep 1.7.0+)
- the refusal of patterns mode (`--pattern`), which opengrep runs only with a
  language that no option of this scanner supplies
"""

from __future__ import annotations

import logging
import platform
import sys
from pathlib import Path
from typing import Annotated, ClassVar, Dict, List, Literal

from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    git_config_env,
    safe_directories_for,
)
from automated_security_helper.base.options import ScannerOptionsBase, release_tag
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    DEFAULT_EXCLUDES,
    GREP_SHARED_FACETS,
    GrepMetricsMode,
    GrepScannerBase,
    GrepSeverityWord,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.download_utils import (
    create_url_download_command,
    get_opengrep_url,
    pinned_tool_install_commands,
)
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import (
    find_executable,
    in_tree_refusal,
    spawn_run,
)
from automated_security_helper.utils.process_env import snapshot_environ


class OpengrepScannerConfigOptions(ScannerOptionsBase):
    config: Annotated[
        str,
        Field(
            description="YAML configuration file, directory of YAML files ending in .yml|.yaml, URL of a configuration file, or Opengrep registry entry name. Defaults to 'p/ci' for consistent results across online and offline modes.",
        ),
    ] = "p/ci"

    exclude: Annotated[
        List[str],
        Field(
            description="Skip any file or directory whose path matches the pattern.",
        ),
    ] = list(DEFAULT_EXCLUDES)

    exclude_rule: Annotated[
        List[str],
        Field(description="Skip any rule with the given id."),
    ] = []

    severity: Annotated[
        List[GrepSeverityWord],
        Field(
            description="Report findings only from rules matching the supplied severity level.",
        ),
    ] = []

    metrics: Annotated[
        GrepMetricsMode,
        Field(
            description="Configures how usage metrics are sent to the OpenGrep server. Deprecated in Opengrep v1.7.0+. This configuration is ignored if the installed version is >= 1.7.0.",
        ),
    ] = "auto"

    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, using locally cached rules. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]

    patterns: Annotated[
        List[str],
        Field(description="Patterns to search for with OpenGrep."),
    ] = []

    # The pinned version, read from the table rather than restated, so the default
    # and the digests it is verified against cannot name different releases.
    version: Annotated[
        str,
        release_tag("scanners.opengrep.options.version"),
        Field(description="Version of OpenGrep to use."),
    ] = TOOL_VERSIONS["opengrep"]

    # Required for any version other than the pinned one. ASH installs no binary it
    # cannot verify, and it only carries digests for the version it pins, so a
    # custom version has to bring its own. Keyed per platform because opengrep
    # publishes a different executable for each, and a platform left out is refused
    # rather than installed unverified.
    sha256: Annotated[
        Dict[
            Literal[
                "linux/amd64",
                "linux/arm64",
                "darwin/amd64",
                "darwin/arm64",
                "windows/amd64",
            ],
            Annotated[str, Field(pattern=r"^[0-9a-fA-F]{64}$")],
        ],
        Field(
            description=(
                "SHA256 of the OpenGrep release asset for a custom `version`, keyed "
                "by platform/arch (e.g. linux/amd64). Required for any version other "
                "than the one ASH pins; ignored for the pinned version, whose digests "
                "ship with ASH. Get it from GitHub's per-asset digest for the "
                "release, or by running sha256sum on the downloaded asset."
            ),
        ),
    ] = {}


class OpengrepScannerConfig(ScannerPluginConfigBase):
    name: Literal["opengrep"] = "opengrep"
    # Off by default on Windows. The schema says the shipped default (on), so the
    # committed schema is the same whichever system generated it.
    enabled: bool = Field(
        default=platform.system().lower() != "windows",
        json_schema_extra={"default": True},
    )
    options: Annotated[
        OpengrepScannerConfigOptions, Field(description="Configure Opengrep scanner")
    ] = OpengrepScannerConfigOptions()


def unverified_version_refusal(
    version: str, target_platform: str, arch: str, asset: str
) -> str:
    """The message a custom opengrep version without a digest is refused with."""
    pinned = TOOL_VERSIONS["opengrep"]
    return (
        f"Refusing to install opengrep {version} on {target_platform}/{arch}: ASH pins "
        f"opengrep {pinned}, and the configuration supplies no SHA256 for "
        f"{target_platform}/{arch}, so the download could not be verified. Either drop "
        f"scanners.opengrep.options.version to use the pinned {pinned}, or add the "
        f"digest of the release asset {asset} under "
        f'scanners.opengrep.options.sha256 as "{target_platform}/{arch}": '
        f'"<sha256>". Get it from the digest GitHub lists for that asset '
        f"(gh api repos/opengrep/opengrep/releases/tags/{version} --jq "
        f"'.assets[] | select(.name == \"{asset}\") | .digest'), or by running "
        f"sha256sum {asset} on the downloaded asset."
    )


def _refuse_unverified_install_command(
    version: str, target_platform: str, arch: str, asset: str
) -> CustomCommand:
    """An install command that prints the refusal and exits 1, installing nothing.

    ``sys.exit`` with a string writes it to stderr and exits 1, so the installer
    counts the command as failed and shows why. The message travels as an argument
    rather than inside the ``-c`` source, so nothing in it is interpreted as code.
    """
    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            "import sys; sys.exit(sys.argv[1])",
            unverified_version_refusal(version, target_platform, arch, asset),
        ],
        shell=False,
    )


def windows_zip_refusal(version: str, asset: str) -> str:
    """The message a custom opengrep 2.x version on Windows is refused with."""
    pinned = TOOL_VERSIONS["opengrep"]
    return (
        f"Refusing to install opengrep {version} on windows/amd64: from 2.0.0 the "
        f"Windows release asset is a zip ({asset}) holding opengrep.exe and the DLLs "
        f"it loads, and a configured version is downloaded as a single file. Drop "
        f"scanners.opengrep.options.version to use the pinned {pinned}, whose zip ASH "
        f"extracts and verifies member by member, or install opengrep {version} "
        f"yourself and put it on PATH."
    )


def _refuse_windows_zip_install_command(version: str, url: str) -> CustomCommand:
    """An install command that prints ``windows_zip_refusal`` and exits 1."""
    return CustomCommand(
        args=[
            sys.executable,
            "-c",
            "import sys; sys.exit(sys.argv[1])",
            windows_zip_refusal(version, url.rsplit("/", 1)[-1]),
        ],
        shell=False,
    )


def _release_number(version: str) -> str:
    """``version`` without the one leading ``v`` a release tag may carry."""
    return version.removeprefix("v")


def _is_pinned_release(version: str) -> bool:
    """Whether ``options.version`` names the pinned release, spelled with or
    without the leading ``v``.

    The validator (``base/options.release_tag``) accepts both spellings, and the
    pinned table spells it with the ``v``, so ``1.30.2`` for a pinned ``v1.30.2``
    used to take the custom-version branch: refused for want of a digest, or
    fetched from a tag without the ``v``, which the release does not carry.
    """
    return _release_number(version) == _release_number(TOOL_VERSIONS["opengrep"])


def _install_arch() -> str:
    """The architecture key of ``custom_install_commands`` for this host.

    From the machine name, as ``cli/dependencies.get_architecture`` reads it:
    ``amd64`` for x86_64 and ``arm64`` for aarch64. The pointer size used to
    decide it, which read every 64-bit host, an arm64 one included, as amd64.
    """
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


def patterns_mode_refusal(patterns: List[str]) -> str:
    """The message a configuration that sets ``options.patterns`` is refused with.

    It names the option, the language option opengrep needs for a ``--pattern``
    search and that this scanner has none, and the supported shape for several
    patterns: a rule file named with ``options.config``, where each rule carries
    its own language.
    """
    count = len(patterns)
    return (
        "opengrep patterns mode is refused: scanners.opengrep.options.patterns "
        f"names {count} pattern{'' if count == 1 else 's'}, and opengrep runs a "
        "--pattern search only with a language (its --lang option), which no "
        "option of this scanner supplies. Write the patterns as rules in a rule "
        "file, which carries several patterns each with its language, and name "
        "the file with scanners.opengrep.options.config; or clear patterns to "
        "scan with the configured rules."
    )


@ash_scanner_plugin
class OpengrepScanner(GrepScannerBase[OpengrepScannerConfig]):
    """OpengrepScanner implements code scanning using Opengrep."""

    display_name = "Opengrep"
    docs_summary = "Pattern-based code checks"
    covers = ("Multiple languages",)

    #: opengrep is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.opengrep",),
        # opengrep keeps semgrep's rule: its log and settings go to
        # $XDG_CONFIG_HOME/.opengrep when that is set.
        cache_env=("XDG_CONFIG_HOME",),
        env_prefixes=("OPENGREP_", "SEMGREP_"),
        # The macOS binary is a Nuitka onefile build that unpacks itself to
        # {CACHE_DIR}/opengrep/<version>, which is $XDG_CACHE_HOME when set, and
        # runs opengrep.bin from there.
        unpack_dir_env="XDG_CACHE_HOME",
        # From 2.0.0 ("Remove python") opengrep downloads rulesets itself, through
        # OCaml's ca-certs like semgrep-core, which on macOS runs /usr/bin/security
        # against the system keychains. Without the exported roots a sandboxed run
        # ends "Error: fatal error" on the p/ci download.
        system_trust_roots=True,
        # The offline rule cache ASH checked before the scan and passes as --config.
        read_path_env=("OPENGREP_RULES_CACHE_DIR",),
        # extra_subprocess_env's safe.directory entries: the sandbox's allowlist
        # passes no GIT_CONFIG_* variable, so it writes them from the directories
        # it computes from the scan target (safe_directories_for) instead.
        git_safe_directory=True,
    )

    #: The facets register row (base/scanner_facets.py). Declaration only, zero
    #: behavior change: opengrep's own SARIF is validated and passed through
    #: without result edits, so every native field is a field of that SARIF.
    #: The cells it shares with semgrep live in GREP_SHARED_FACETS
    #: (_grep_scanner_base.py); the three below are this tool's own.
    #: Fingerprints are settled by the M0 capture
    #: (tests/test_data/scanners/opengrep/captured/opengrep-2.0.0-m0.sarif):
    #: the fork emits a real matchBasedId/v1, not the semgrep OSS login
    #: placeholder.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        **GREP_SHARED_FACETS,
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='results[].fingerprints."matchBasedId/v1"',
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="opengrep 2.0.0's SARIF has no fixes key even for a rule "
            "that carries `fix:` (tests/test_data/scanners/opengrep/captured/"
            "opengrep-2.0.0-fix-rule.sarif: result keys are exactly "
            "fingerprints, locations, message, properties, ruleId), so there "
            "is nothing in the SARIF ASH reads to map",
        ),
        references=FacetDecl(
            state=FacetState.UNCONFIRMED,
            reason="UNCONFIRMED: the committed captures' SARIF rules carry no "
            "helpUri (the rule help is help.markdown text, not a link). A "
            "rule helpUri would be read into the flat references by the "
            "shared rule read (FlatVulnerability.from_sarif_result); "
            "redeclare MAPPED when a capture carrying one is committed (the "
            "corpus gate lists this cell as a fixture owed until then)",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="opengrep",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.RULESET_REGISTRY,),
                prefetch=(opsf.Prefetch.IMAGE_BUILD,),
                offline_outcome=opsf.OfflineOutcome.DEGRADED,
                offline_reason=(
                    "runs against the operator's local rules or the validated offline "
                    "ruleset cache as --config; opengrep runs once, and a registry "
                    "ruleset it cannot download exits 2 and ends the scan as a fatal "
                    "scanner error, with no second run on the local configs"
                ),
                offline_strategy=OfflineStrategy.CACHE_FLAGS,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                content_database="opengrep-offline-rules",
                source=(
                    "opengrep_scanner.py sandbox_requirements and default rulesets; "
                    "_grep_scanner_base.py offline_strategy; utils/content_databases.py"
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
                    "whole scan set, languages defined by the ruleset; .semgrepignore "
                    "normalized to ASH's ignore model (_grep_scanner_base.py)"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key="opengrep",
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_NO_WINDOWS_ARM64,
                note=(
                    "one static Linux build per architecture since v2.0.0; no "
                    "windows/arm64 asset (tool_downloads.py _OPENGREP_ASSETS)"
                ),
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the SARIF level only: three grades",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".semgrepignore in the scanned tree",
                        cite="_grep_scanner_base.py:359-375; ASH warns and names global_settings.ignore_paths",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_NATIVE,
                note=(
                    "matchBasedId/v1, read in tests/test_data/scanners/opengrep/"
                    "captured/opengrep-2.0.0-m0.sarif (results[].fingerprints)"
                ),
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.BOTH,
                env_prefixes=("OPENGREP_", "SEMGREP_"),
                options_surface=(
                    "options.config: a registry entry, a URL, or a local rule file or "
                    "directory through the path-trust resolver; a refused or missing "
                    "value declines the scanner"
                ),
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics=(
                    "the base default {0, 1}; opengrep runs once, and exit 2 (a ruleset "
                    "download failed) and exit 7 (a downloaded ruleset is invalid YAML) "
                    "are fatal scanner errors"
                ),
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=("options.config",),
                upstream_license=(
                    "LGPL-2.1-only (source: utils/tool_downloads.py "
                    "THIRD_PARTY_LICENSES['opengrep'], pinned commit 526deaf)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note=(
                    "no prerequisite: opengrep 2.0.0 (the pinned release, sha256 checked) "
                    "scanned a copy of tests/test_data/scanners/opengrep/fixture_repo with "
                    "no .git directory and exited 0 with the one finding it reports on a "
                    "git copy of the same files. In a git checkout it runs git ls-files "
                    "itself and exits 2 when git refuses the directory; ASH supplies "
                    "safe.directory"
                ),
            ),
        )
    )

    def model_post_init(self, context):
        if self.config is None:
            self.config = OpengrepScannerConfig()
        self.command = "opengrep"
        self.subcommands = ["scan"]
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-output",
            scan_path_arg=None,
            extra_args=[],
        )
        self._constructing = True
        try:
            super().model_post_init(context)
        finally:
            self._constructing = False

    # Whether --metrics applies depends on the installed opengrep's version, and
    # asking starts opengrep. The arguments are built at construction, which the scan
    # phase does for every registered scanner, selected or not, so the question
    # waits for _resolve_scan_arguments.
    _constructing: bool = PrivateAttr(default=False)
    _metrics_decision_pending: bool = PrivateAttr(default=False)
    # The answer, once asked, so the arguments rebuilt with it do not ask again.
    _metrics_flag: bool | None = PrivateAttr(default=None)
    # The directory this scan was pointed at, set by _resolve_scan_arguments for
    # extra_subprocess_env.
    _scan_target_path: Path | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "OpengrepScanner":
        """Set up custom installation commands for opengrep.

        No path installs an unverified binary.

        * The pinned version, spelled with or without its leading ``v``
          (``_is_pinned_release``), is installed from ``utils/tool_downloads.py``,
          verified against its SHA256 before it is put on disk, exactly as grype,
          syft and trivy are.
        * A custom ``version`` is installed only on a platform for which the
          configuration supplies ``sha256``, and goes through the same verified
          download, failing closed on a mismatch.
        * A custom ``version`` with no digest for a platform gets a command that
          refuses, naming the key to add and how to obtain the value.

        Before this, every install fetched the release asset by URL with no digest
        at all, so the binary a SAST scan then trusted was whatever that URL served.
        The refusal is an install command rather than a validation error on purpose:
        a config naming a custom version must still load, so a host that already has
        opengrep can scan with it, and only the install is refused.
        """
        version = self.config.options.version
        if _is_pinned_release(version):
            self.custom_install_commands.update(
                pinned_tool_install_commands("opengrep")
            )
            return self

        digests = self.config.options.sha256
        # TODO: detect manylinux vs musllinux. Only matters for a 1.x version: from
        # 2.0.0 the Linux build is one static executable (get_opengrep_url).
        for target_platform, arch in (
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        ):
            url = get_opengrep_url(
                target_platform, arch, version=version, linux_type="manylinux"
            )
            digest = digests.get(f"{target_platform}/{arch}")
            if url.endswith(".zip"):
                # From 2.0.0 the Windows asset is a zip of opengrep.exe and its DLLs.
                # The URL download installs the file it fetches as the executable, so
                # a zip would land at opengrep.exe unextracted. Only the pinned
                # version has the archive handling (tool_downloads.py), so this
                # refuses whether or not a digest was configured.
                command = _refuse_windows_zip_install_command(version, url)
            elif digest is None:
                command = _refuse_unverified_install_command(
                    version, target_platform, arch, url.rsplit("/", 1)[-1]
                )
            else:
                command = create_url_download_command(
                    url=url,
                    rename_to=(
                        "opengrep.exe" if target_platform == "windows" else "opengrep"
                    ),
                    expected_sha256=digest,
                )
            self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                command
            ]
        return self

    # ---------------------------------------------------------------
    # GrepScannerBase hooks
    # ---------------------------------------------------------------

    def cache_dir_env_var(self) -> str:
        return "OPENGREP_RULES_CACHE_DIR"

    def cache_dir_name(self) -> str:
        return "Opengrep"

    def default_rulesets(self) -> List[str]:
        return ["p/ci"]

    def emit_metrics_flag(self) -> bool:
        """`--metrics` was removed in opengrep 1.7.0; only emit on older versions.

        During construction the answer is no, and the question is left for
        ``_resolve_scan_arguments``.
        """
        if self._constructing:
            self._metrics_decision_pending = True
            return False
        if self._metrics_flag is None:
            self._metrics_flag = self._should_use_metrics_flag()
        return self._metrics_flag

    def _resolve_scan_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The arguments, with ``--metrics`` decided on the first call.

        Construction built them without ``--metrics``, which is right for the pinned
        version and any 1.7.0 or later. For an older opengrep they are built again,
        the same way, with it.

        Decided here and not inside ``_resolve_arguments``: the base's
        ``_resolve_scan_arguments`` adds this target's excludes to ``extra_args``
        around that call and restores the list it saved afterwards, so a rebuild
        inside it was thrown away (every later target lost ``--metrics``) and the
        first target's command lost the output-directory excludes the rebuild
        replaced.

        The rebuild runs the offline-cache validation again, after
        ``_execute_scan`` checked the reason construction recorded. A cache that
        became unusable since then is recorded the same way, and the scan is
        refused here rather than run with no cache ``--config`` and graded.
        """
        if self._metrics_decision_pending:
            self._metrics_decision_pending = False
            if self.emit_metrics_flag():
                self.args.extra_args = []
                self._process_config_options()
                if self.dependency_unavailable_reason:
                    raise ScannerError(self.dependency_unavailable_reason)
        self._scan_target_path = target
        return super()._resolve_scan_arguments(target, results_file)

    def extra_subprocess_env(self) -> dict | None:
        """Git's ``safe.directory`` for the one directory this scan reads.

        opengrep 2.0.0 lists files with ``git ls-files`` itself and exits 2 when git
        refuses the directory ("Could not get files from git ls-files"), which it
        does for a mount another user owns (the container scans). 1.33.1 tolerated
        that. The entry reaches only this child, through ``GIT_CONFIG_*``, and names
        the real path of the scanned directory, never ``*``; ASH's own git calls
        and every other process keep the ownership check.

        Git compares ``safe.directory`` with the top of the work tree, so a scan
        pointed at a subdirectory of a checkout names the checkout's top level as
        well: the first parent that holds a ``.git`` the scanned directory's owner
        also owns, and never a filesystem root (``safe_directories_for``). Outside a
        checkout only the scanned directory is named.

        A sandboxed spawn reads the same list from the policy, which computes it
        from the scan target with the same function, and rebuilds the entries
        itself (``SandboxPolicy.filter_env``); no environment variable carries it.
        The direct spawn uses the ``GIT_CONFIG_*`` entries built here, numbered
        after the caller's own block when that block is whole.
        """
        target = self._scan_target_path
        if target is None:
            return None
        directories = safe_directories_for(target)
        if not directories:
            return None
        return git_config_env(snapshot_environ(), directories)

    # ---------------------------------------------------------------
    # Dependency resolution
    # ---------------------------------------------------------------

    def _validate_tool_dependencies(self) -> bool:
        """Opengrep's tool-reachability check.

        Named for the ``GrepScannerBase`` hook rather than overriding
        ``validate_plugin_dependencies`` directly: the base method now consults the
        offline-cache verdict first, and an override here would skip it.

        A copy found only inside the scanned tree is refused by the lookup
        (``subprocess_utils.find_executable``); the reason is recorded for the
        MISSING row, as ``ScannerPluginBase.validate_plugin_dependencies`` records
        it, so the row says where the copy is and how to allow it rather than
        "not installed".
        """
        found = find_executable(self._tool_command())
        ASH_LOGGER.verbose(f"Found opengrep executable at: {found}")
        if found is None:
            refusal = in_tree_refusal(self._tool_command())
            if refusal is not None:
                self.dependency_unavailable_reason = refusal
                self._plugin_log(refusal, level=logging.WARNING)
        return found is not None

    def _has_install_commands(self) -> bool:
        system = platform.system().lower()
        arch = _install_arch()
        if system in self.custom_install_commands:
            if arch in self.custom_install_commands[system]:
                return len(self.custom_install_commands[system][arch]) > 0
        return False

    # ---------------------------------------------------------------
    # Version detection (used to gate --metrics)
    # ---------------------------------------------------------------

    def _get_opengrep_version(self) -> tuple[int, int, int] | None:
        try:
            result = spawn_run(  # nosec B603 — list args, executable from find_executable()
                [self._tool_command(), "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                env=snapshot_environ(),
            )
            if result.returncode == 0:
                version_str = result.stdout.strip().split()[-1].lstrip("v")
                parts = version_str.split(".")
                if len(parts) >= 3:
                    return (int(parts[0]), int(parts[1]), int(parts[2]))
        except FileNotFoundError:
            return None
        except Exception as e:
            ASH_LOGGER.verbose(f"Unable to determine Opengrep version: {e}")
        return None

    def _should_use_metrics_flag(self) -> bool:
        version = self._get_opengrep_version()
        if version is None:
            ASH_LOGGER.verbose(
                "Unable to determine Opengrep version, assuming --metrics is NOT supported (default version >= 1.7.0)"
            )
            return False
        if version >= (1, 7, 0):
            ASH_LOGGER.verbose(
                f"Opengrep version {'.'.join(map(str, version))} detected, skipping --metrics flag"
            )
            return False
        ASH_LOGGER.verbose(
            f"Opengrep version {'.'.join(map(str, version))} detected, using --metrics flag"
        )
        return True

    # ---------------------------------------------------------------
    # Patterns mode — refused
    # ---------------------------------------------------------------

    def _process_config_options(self):
        """The shared argument build, after refusing patterns mode.

        ``options.patterns`` used to switch the command to one ``--pattern`` per
        entry with JSON output. opengrep runs a ``--pattern`` search only with a
        language (``--lang``), which no option of this scanner carries, so every
        such command was built, started and failed at the tool, and the report
        showed a tool failure for a configuration opengrep can never run. The
        refusal is raised here, while the scanner is built and before any argument
        exists: the scan phase records a scanner whose constructor raised as that
        scanner's ERROR with this text, so the report names the option and what to
        write instead, and a run that did not select opengrep records it as not
        selected, as for any other construction-time refusal.
        """
        if self.config.options.patterns:
            raise ScannerError(patterns_mode_refusal(self.config.options.patterns))
        return super()._process_config_options()
