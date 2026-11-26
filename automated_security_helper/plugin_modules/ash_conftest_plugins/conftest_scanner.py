# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Conftest: policy tests over configuration files, as an alpha scanner plugin.

What it runs
------------
``conftest test`` over the configuration files of the scan target, against Rego
policies the operator supplies. Conftest ships no rules (by design), so this scanner
does nothing until a policy directory exists. Its own convention is ``policy/``.

Conftest is an alpha plugin: it is loaded only when ``ash_conftest_plugins`` is
listed in ``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``).

Install
-------
The tool is the pinned Conftest release in ``utils/tool_downloads.py`` (v0.62.0: one
archive per platform, a SHA256 for each archive and for the executable inside it,
and the license entry). ``ash dependencies install --tool conftest`` installs it and
the container image carries it; a ``conftest`` already on ``PATH`` is used as is.

In Nix mode the repository flake supplies Conftest from nixpkgs instead, at the
version the flake lock carries: 0.63.0 at the locked revision, not the v0.62.0 pin.
None of the files "Invocation" below is read from differs between the v0.62.0 and
v0.63.0 tags; v0.63.0 is built with OPA 1.9.0 where v0.62.0 has OPA 1.6.0.

The policy gate
---------------
Like ``snyk-code``, which waits for its credential, this scanner has a precondition
that is the operator's to meet: a policy directory holding at least one ``.rego``
file. When there is none, ``scan()`` does not start the tool. It logs one INFO line,
records a "nothing scanned" reason, and returns, so the row reads SKIPPED and not
PASSED. ``nothing_to_scan_reason`` gives the same reason when the tool is also
missing, so a tree with no policies reads SKIPPED, not MISSING. The directory is
``options.policy_dir`` (default ``policy``), taken from the source directory.

Invocation
----------
Read from the Conftest source at v0.62.0, the pinned release (tag commit
``ebb167d2``): ``internal/commands/test.go``, ``runner/test.go``, ``output/sarif.go``,
``output/output.go``, ``output/result.go``, ``parser/parser.go`` and ``main.go``.

* ``--output=sarif``: SARIF 2.1.0 on stdout. The scanner writes it to its results
  file, where the template ``scan()`` reads it. An output name Conftest does not know
  falls back to its plain text format, which is not JSON and fails the scan.
* ``--no-fail``: exit 0 although a policy failed. Conftest exits 1 both for a failed
  policy and for an error (an unparseable file, a bad policy), and ``--no-fail`` is
  what separates them: with it 0 is "ran to completion" and anything else is a
  failure. So ``success_exit_codes`` is ``{0}``.
* ``--no-color``, ``--policy=<dir>``, ``--all-namespaces`` (default on, because
  Conftest tests only the ``main`` namespace otherwise and a policy package named
  anything else would never run).
* The files follow ``--``. A file named on the command line is always parsed, and one
  no parser claims fails the whole run (``unknown parser``). A directory argument
  would be walked by Conftest itself: it follows symbolic links, out of the tree too,
  walks ``.git``, ``node_modules``, the policy directory and ASH's output alike, and
  reads a file with no extension that is not a Dockerfile (a ``Makefile``, a
  ``LICENSE``) as YAML, so one such file that is not YAML fails the run. So ASH lists
  the files itself, by the names and extensions v0.62.0 routes to a parser
  (``SUPPORTED_EXTENSIONS``, ``SUPPORTED_NAMES``), and passes no directory.
* The working directory is the source directory and paths are passed relative to it,
  so reported URIs are source-relative.

Severity
--------
Conftest SARIF carries a ``level`` per result: ``deny`` rules are ``error``, ``warn``
rules ``warning``, ``allow`` exceptions ``note``, and a file with no failure and no
warning gets one ``none`` result, "Policy was satisfied successfully" when a rule
passed or an exception applied and "Policy check was skipped" when none did. ASH
drops the ``note`` and ``none`` results, since they are not findings, and rates the
rest so that ``issue_severity`` and the SARIF level agree:

* ``error`` -> HIGH / ``error`` (policy violation, not the CRITICAL a generic error
  maps to: the policy author's rule is a requirement, not a proven exploit)
* ``warning`` -> MEDIUM / ``warning``
* no level -> MEDIUM / ``warning``
* any other level -> HIGH / ``error``, the more severe choice

Exit status and output
----------------------
0 is success. Stderr is not copied into the scan's errors: Conftest quotes the text of
the file it could not parse.

Offline
-------
Conftest makes no network call unless a policy does (``http.send``) or ``--update``
is passed, which ASH never does. The strict sandbox has no network.

Sandbox
-------
The strict default. Policies from the scanned tree are code Conftest evaluates; they
run inside it.
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
from automated_security_helper.utils.config_trust import (
    leaves_the_tree_through_a_link,
    operator_path,
    refusal_warning,
    scan_root,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.scan_targets import scan_targets
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import downloadable_tools

#: The tool's key in ``tool_downloads`` (``TOOL_VERSIONS``, the asset tables).
CONFTEST_TOOL_NAME = "conftest"

#: The directory Conftest reads policies from when ``--policy`` is not passed.
DEFAULT_POLICY_DIR = "policy"

#: Extensions the pinned Conftest routes to a parser (``NewFromPath`` in
#: ``parser/parser.go`` at the v0.62.0 tag commit, ebb167d2). The release parses a
#: few more that ASH does not list (``.env``, ``.textproto``, ``.textpb``, ``.spdx``,
#: ``.gitignore``); a file left out is not scanned, while a file listed that no
#: parser claims fails the whole run.
SUPPORTED_EXTENSIONS = frozenset(
    {
        ".yaml",
        ".yml",
        ".json",
        ".jsonc",
        ".toml",
        ".hcl",
        ".tf",
        ".tfvars",
        ".ini",
        ".xml",
        ".properties",
        ".cue",
        ".jsonnet",
        ".edn",
        ".vcl",
        ".hocon",
        ".dockerfile",
    }
)

#: File names the pinned Conftest routes to a parser whatever their extension (the
#: same ``NewFromPath``). Later releases also route ``nginx.conf`` (v0.71.1 does);
#: v0.62.0 has no such parser and fails the whole run on a listed ``nginx.conf``
#: ("unknown parser: conf"), so it is not listed. Moving the pin means reading
#: ``NewFromPath`` again at the new tag before this set or the one above changes.
SUPPORTED_NAMES = frozenset({"dockerfile"})

#: Directories never walked.
SKIPPED_DIRS = frozenset({".git", "node_modules", ".venv", "__pycache__"})

#: Rule id suffixes of Conftest's results that are not findings.
NON_FINDING_RULE_SUFFIXES = ("/success", "/skip", "/allow")

#: Most characters of file arguments one run carries. Windows allows about 32 KB for a
#: whole command line, other platforms far more.
MAX_ARGV_CHARS = 30_000 if os.name == "nt" else 100_000

#: SARIF level -> (level written back, ASH severity). See "Severity" above.
CONFTEST_LEVEL_MAP: Dict[str, Tuple[Level, str]] = {
    "error": (Level.error, "HIGH"),
    "warning": (Level.warning, "MEDIUM"),
}
_MISSING_LEVEL = (Level.warning, "MEDIUM")
_UNKNOWN_LEVEL = (Level.error, "HIGH")


class ConftestScannerConfigOptions(ScannerOptionsBase):
    policy_dir: Annotated[
        str | None,
        Field(
            description=(
                "Directory of Rego policies, relative to the source directory or "
                f"absolute. Unset means ``{DEFAULT_POLICY_DIR}``. Conftest ships no "
                "rules: with no .rego file there, the scanner does nothing and "
                "reports SKIPPED."
            ),
        ),
    ] = None
    all_namespaces: Annotated[
        bool,
        Field(
            description=(
                "Test the policies of every namespace (Rego package). Conftest "
                "tests only `main` by default."
            ),
        ),
    ] = True


class ConftestScannerConfig(ScannerPluginConfigBase):
    name: Literal["conftest"] = "conftest"
    enabled: bool = True
    options: Annotated[
        ConftestScannerConfigOptions,
        Field(description="Configure the conftest scanner"),
    ] = ConftestScannerConfigOptions()


@ash_scanner_plugin
class ConftestScanner(ScannerPluginBase[ConftestScannerConfig]):
    """Rego policy tests over configuration files using Conftest."""

    #: A native binary, installed from its pinned release asset (``tool_downloads``).
    python_only: ClassVar[bool | None] = False

    # No network at scan time unless a policy asks for one, which the sandbox refuses.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # Run with --no-fail: 0 is "ran to completion", anything else is a failure.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name Conftest's SARIF (``output/sarif.go``); the captured report is
    #: tests/test_data/scanners/conftest/captured/positive.sarif.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId" (<namespace>/<deny|warn>)',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "level" (error, warning), rewritten by '
            '_post_process_sarif together with properties "issue_severity"',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="locations[].physicalLocation.artifactLocation.uri",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="Conftest SARIF carries no region: a policy result names the "
            "file, not a line",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="Conftest SARIF carries no region",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "message.text" (the policy author\'s msg)',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="a policy result names a file and a message, not a deployable "
            "resource; the rule id is the policy's, not an infrastructure address",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries no resource type",
        ),
        package_name=FacetDecl(
            state=FacetState.NA, reason="policy findings carry no package"
        ),
        package_version=FacetDecl(
            state=FacetState.NA, reason="policy findings carry no package"
        ),
        package_path=FacetDecl(
            state=FacetState.NA, reason="policy findings carry no package"
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA, reason="policy findings carry no CVE taxonomy"
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="Conftest rules are the operator's Rego; none carries a CWE",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries no fingerprints",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA, reason="policy findings carry no fix state"
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF carries the policy message only",
        ),
        snippet=FacetDecl(
            state=FacetState.NA, reason="the SARIF carries no source snippet"
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry an id, a short description and "
            "properties, but no help URI or reference URL",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native tags) the adapter writes policy and "
            "conftest into result properties tags",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" written by the adapter',
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py). Conftest
    #: is pinned in ``tool_downloads`` (v0.62.0, every platform ASH installs on), so
    #: its runtime is the pinned binary.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="conftest",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "conftest_scanner.py offline_strategy, sandbox_requirements; "
                    "module header (Offline): no network unless a policy calls "
                    "http.send, and ASH never passes --update"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
                note="--output=sarif on stdout, written to conftest.sarif by the scanner",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.IAC_OTHER,),
                tool_type=ScannerToolType.IAC,
                selection="the files under the target whose name or extension the "
                "pinned Conftest routes to a parser, listed by _config_files and "
                "passed after `--`",
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key=CONFTEST_TOOL_NAME,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for Conftest.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_ALL,
                note="the v0.62.0 release publishes darwin, linux and windows "
                "archives for amd64 and arm64 (plus linux ppc64le and s390x "
                "archives and .deb/.rpm packages, which ASH does not install); "
                "derived from tool_downloads",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="the policy's own deny/warn level: error -> HIGH, warning -> "
                "MEDIUM, any other level HIGH (CONFTEST_LEVEL_MAP)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.TOOL_DEFAULT_FILTER,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="`exception` rules in the Rego policies, which Conftest "
                        "reports as allow results",
                        cite="conftest_scanner.py NON_FINDING_RULE_SUFFIXES and "
                        "_post_process_sarif: allow, success and skip results are dropped",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the SARIF carries no fingerprints and no line, so identity is "
                "the file and the rule id",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.OPERATOR_PATHS,
                env_prefixes=(),
                options_surface="options.policy_dir, a directory of Rego policies "
                "(default policy/ under the source directory); Conftest ships no rules",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="ASH passes --no-fail, so 0 is ran to completion and any "
                "other status is a failure (Conftest exits 1 for a failed policy "
                "and for an error alike)",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=(
                    "ash_conftest_plugins in ash_plugin_modules",
                    "options.policy_dir",
                ),
                upstream_license=(
                    "Apache-2.0 (source: LICENSE in conftest_0.62.0_Linux_x86_64.tar.gz, "
                    "sha256 a3fc6a99a82b59b761a6b1aabe8fc540b7046d5f91377fc1d8897dbbf3bd18ac, "
                    "byte-identical in the six pinned archives and to the repository "
                    "LICENSE at the v0.62.0 commit)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="a Rego policy directory is the operator's input, not a "
                "prerequisite file kind; without one the scan reads SKIPPED",
            ),
        )
    )

    _results_file: Optional[Path] = PrivateAttr(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ConftestScannerConfig()
        self.command = "conftest"
        self.subcommands = ["test"]
        self.tool_type = ScannerToolType.IAC
        # The argv is assembled in _execute_scan.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "ConftestScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``.

        The pin (v0.62.0: six release assets, a SHA256 for each archive and for the
        executable inside it, and the license entry) lives in that shared table. A
        build whose table has no ``conftest`` row would make
        ``pinned_tool_install_commands`` raise ``ToolNotProvisionableError`` and the
        scanner impossible to construct, so that case leaves the install table empty
        instead, and ``validate_plugin_dependencies`` says so. A pair with no command
        is left absent, never an empty list, so ASH does not report an install it did
        not do.
        """
        try:
            self.custom_install_commands.update(
                pinned_tool_install_commands(CONFTEST_TOOL_NAME)
            )
        except ToolNotProvisionableError:
            pass
        return self

    # ------------------------------------------------------------------
    # Inputs and the policy gate
    # ------------------------------------------------------------------

    def _options(self) -> ConftestScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, ConftestScannerConfigOptions):
            return options
        return ConftestScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("ConftestScanner has no plugin context")
        return Path(self.context.source_dir)

    def _policy_choice(self) -> Tuple[Path, bool]:
        """The policy directory and whether it is the default ``policy/``.

        Rego is code Conftest evaluates, so which directory it comes from is the
        operator's choice (``config_trust.operator_path``): a ``policy_dir`` the
        scanned repository's own config or an MCP client set, or one that leads out
        of the tree through a symbolic link, is ignored with one warning and the
        default ``policy/`` under the source directory is used. A directory the
        operator wrote may sit inside the tree.
        """
        source = self._source_dir()
        value = self._options().policy_dir
        if value:
            config = self.context.config if self.context is not None else None
            chosen = operator_path(
                config,
                "scanners.conftest.options.policy_dir",
                value,
                source,
                outside_tree=False,
            )
            if chosen.path is not None:
                return chosen.path, False
            key = f"policy_dir:{value}"
            if key not in self._operator_refusals_logged:
                self._operator_refusals_logged.add(key)
                self._plugin_log(
                    refusal_warning(
                        f"Ignoring scanners.conftest.options.policy_dir "
                        f"({str(value)!r}): {chosen.refusal}. Using "
                        f"{DEFAULT_POLICY_DIR}/ under the source directory.",
                        chosen.refusal,
                    ),
                    level=logging.WARNING,
                )
        return source / DEFAULT_POLICY_DIR, True

    def _policy_path(self) -> Path:
        return self._policy_choice()[0]

    def _policy_gate_reason(self) -> Optional[str]:
        """Why there is nothing to run, or None when the policy directory has Rego."""
        policy, is_default = self._policy_choice()
        if is_default and self.context is not None:
            source = self._source_dir()
            config = self.context.config
            if leaves_the_tree_through_a_link(
                DEFAULT_POLICY_DIR, source, scan_root(config, source)
            ):
                return (
                    f"conftest has no policies to test: {policy.as_posix()} resolves "
                    "outside the scanned tree through a symbolic link, so the "
                    "scanned repository would decide which Rego Conftest "
                    "evaluates. Name the directory in "
                    "scanners.conftest.options.policy_dir."
                )
        try:
            has_rego = policy.is_dir() and any(
                p.suffix == ".rego" and p.is_file() for p in policy.rglob("*.rego")
            )
        except OSError:
            has_rego = False
        if has_rego:
            return None
        return (
            f"conftest has no policies to test: no .rego file under "
            f"{policy.as_posix()} (set scanners.conftest.options.policy_dir). "
            "Conftest ships no rules."
        )

    def _no_files_reason(self, target: Path) -> Optional[str]:
        """Why ``target`` holds nothing Conftest can parse, or None when it does."""
        if self._config_files(target):
            return None
        return (
            "no file Conftest can parse was found in the target (it parses yaml, "
            "json, toml, hcl, terraform, Dockerfile, ini, xml and a few more)"
        )

    def nothing_to_scan_reason(self) -> Optional[str]:
        """The policy gate's reason, or the lack of any parsable file in every tree.

        Answers for the trees a scan hands the scanner (``scan_targets``): a reason
        only when ``scan()`` would start Conftest on none of them.
        """
        reason = self._policy_gate_reason()
        if reason is not None:
            return reason
        if self.context is None:
            return None
        reasons = []
        for _target_type, tree in scan_targets(self.context):
            found = self._no_files_reason(tree)
            if found is None:
                return None
            reasons.append(found)
        return reasons[0] if reasons else None

    def scan(  # type: ignore[override]
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """The template scan, after the policy gate."""
        reason = self._policy_gate_reason()
        if reason is None and Path(target).is_dir():
            # A tree with no parsable file is a scan with nothing to evaluate, not
            # a failed one: the converted tree of a notebook project holds none.
            found = self._no_files_reason(Path(target))
            if found is not None:
                reason = f"{found}."
        if reason is not None:
            self.exit_code = 0
            self._reset_errors()
            self._nothing_scanned_reason = reason
            self._plugin_log(
                f"{reason} Not running the tool on {target_type}.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True
        return super().scan(target, target_type, global_ignore_paths, *args, **kwargs)

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _config_files(self, target: Path) -> List[str]:
        """The files under ``target`` Conftest has a parser for, sorted.

        Paths are relative to the source directory when they sit under it. Links
        are neither followed nor listed, and ASH's output directories are skipped.
        """
        target = Path(target)
        if target.is_file():
            return [target.as_posix()]
        output_dirs = {
            Path(os.path.normpath(target / rel))
            for rel in self._ash_output_dirs_inside(target)
        }
        own = self._output_dir_inside(target)
        if own is not None:
            output_dirs.add(Path(os.path.normpath(target / own)))
        policy = self._policy_path().resolve()
        base = self._source_dir().absolute()
        found: List[str] = []
        for root, dirs, files in os.walk(target, followlinks=False):
            root_path = Path(root)
            dirs[:] = sorted(
                d
                for d in dirs
                if d not in SKIPPED_DIRS
                and not (root_path / d).is_symlink()
                and Path(os.path.normpath(root_path / d)) not in output_dirs
                and (root_path / d).resolve() != policy
            )
            for name in sorted(files):
                path = root_path / name
                lowered = name.lower()
                if path.is_symlink():
                    continue
                if (
                    Path(lowered).suffix not in SUPPORTED_EXTENSIONS
                    and lowered not in SUPPORTED_NAMES
                    and not lowered.startswith("dockerfile.")
                ):
                    continue
                absolute = path.absolute()
                try:
                    found.append(absolute.relative_to(base).as_posix())
                except ValueError:
                    found.append(absolute.as_posix())
        return sorted(found)

    def _build_arguments(self, files: List[str]) -> List[str]:
        args: List[str] = [
            self.command or "conftest",
            *self.subcommands,
            "--output=sarif",
            "--no-fail",
            "--no-color",
            f"--policy={self._policy_path().as_posix()}",
        ]
        if self._options().all_namespaces:
            args.append("--all-namespaces")
        args.append("--")
        args.extend(files)
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Conftest run."""
        if self.results_dir is None:
            raise ScannerError("ConftestScanner has no results directory")
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "conftest.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        files = self._config_files(target)
        if not files:
            raise ScannerError(
                "no file Conftest can parse was found in the target (it parses "
                "yaml, json, toml, hcl, terraform, Dockerfile, ini, xml and a few "
                "more). Conftest is not started."
            )
        if sum(len(f) + 1 for f in files) > MAX_ARGV_CHARS:
            raise ScannerError(
                f"{len(files)} configuration files do not fit on one command line "
                f"({MAX_ARGV_CHARS} characters). Narrow the scan with ASH ignore "
                "paths."
            )
        self._results_file = results_file
        final_args = self._build_arguments(files)
        self._plugin_log(
            f"Running: conftest test over {len(files)} file(s)",
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
        """Run Conftest and write its stdout, the SARIF report, to the results file."""
        kwargs.setdefault("stdout_preference", "return")
        response = super()._run_subprocess(command, results_dir=results_dir, **kwargs)
        stdout = response.get("stdout") if isinstance(response, dict) else None
        if self._results_file is not None and stdout:
            with open_for_write(self._results_file, encoding="utf-8") as handle:
                handle.write(stdout)
        return response

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep stderr, which quotes parsed files, out of errors."""
        super()._process_command_response(
            {
                key: value
                for key, value in response.items()
                if key not in ("stderr", "stdout")
            }
        )

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (conftest was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). conftest's log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop results that are not findings, then rate the rest."""
        for run in sarif_report.runs or []:
            kept = []
            for result in run.results or []:
                level = getattr(result.level, "value", result.level)
                rule = result.ruleId or ""
                if level in ("none", "note") or rule.endswith(
                    NON_FINDING_RULE_SUFFIXES
                ):
                    continue
                kept.append(result)
            run.results = kept
        for result in sarif_report.get_all_results():
            raw = getattr(result.level, "value", result.level)
            if raw is None:
                level, severity = _MISSING_LEVEL
            else:
                level, severity = CONFTEST_LEVEL_MAP.get(str(raw), _UNKNOWN_LEVEL)
            result.level = level
            result.kind = Kind.fail
            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("policy", "conftest"):
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
        found = find_executable(self.command or "conftest")
        if not found:
            if CONFTEST_TOOL_NAME in downloadable_tools():
                ASH_LOGGER.warning(
                    "conftest executable not found in PATH. Install it with "
                    "`ash dependencies install --config-overrides "
                    "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                    "ash_conftest_plugins\"]' --tool conftest`."
                )
            else:
                ASH_LOGGER.warning(
                    "conftest executable not found in PATH, and this ASH build pins "
                    "no conftest release to install. Install Conftest from "
                    "https://github.com/open-policy-agent/conftest/releases and put "
                    "it on PATH."
                )
        return found is not None


__all__ = [
    "CONFTEST_LEVEL_MAP",
    "ConftestScanner",
    "ConftestScannerConfig",
    "ConftestScannerConfigOptions",
    "DEFAULT_POLICY_DIR",
    "SUPPORTED_EXTENSIONS",
]
