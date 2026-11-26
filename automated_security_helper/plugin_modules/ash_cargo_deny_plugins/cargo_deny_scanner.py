# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CargoDenyScanner: Rust dependency advisories and policy checks with cargo-deny.

Alpha plugin. Listing ``automated_security_helper.plugin_modules.ash_cargo_deny_plugins``
in ``ash_plugin_modules`` turns it on; a scan that does not list it is unchanged.

What was MEASURED (cargo-deny 0.21.0, 2026-11-19, linux x86_64 musl asset)
-------------------------------------------------------------------------
Scan flow: this scanner overrides ``scan()`` (the own-scan shape, like hadolint
and guarddog) rather than filling in ``_execute_scan``. cargo-deny does not write
a report file. Its diagnostics are newline-delimited JSON on STDERR with
``--format=json`` (stdout stays empty), and its SARIF writer (``--format=sarif``)
is documented by its changelog as experimental. So the JSON is read and converted
to SARIF here.

Targets: cargo-deny works on a whole Cargo project, not on files. One run is made
per ``Cargo.toml`` that has a ``Cargo.lock`` beside it (a workspace's lock sits at
its root, so members are covered by the root's run and not run again).

Invocation, every flag on the pinned version::

    cargo-deny --manifest-path=<Cargo.toml> --locked --format=json \
      --log-level=warn --color=never --config=<config> \
      check --hide-inclusion-graph <check>...

* ``--manifest-path=...`` takes its value with ``=`` so a path that starts with a
  dash is never read as a flag.
* ``--locked`` makes cargo refuse to create or change ``Cargo.lock``; a project
  with no lock fails ("cannot create the lock file ... because --locked was
  passed") instead of being resolved, and the scanned tree is never written to.
* ``--format=json`` puts one JSON object per line on stderr. ``type`` is
  ``diagnostic``, ``summary`` or ``log``.
* ``--hide-inclusion-graph`` drops the ``graphs`` dependency trees from every
  diagnostic. The crate name and version come from the diagnostic's label span.
* ``--config=<config>`` is always passed (see Configuration).
* The checks (``advisories`` by default) follow ``check`` and come from a fixed
  list, never from the tree.

Exit status: a bitset since cargo-deny 0.14.1, one bit per check that reported at
least one error: advisories 1, bans 2, licenses 4, sources 8 (0..15). A failed
RUN also exits 1: in the measured case (no Cargo.lock under ``--locked``) stderr
held only ``type: log`` lines at level ERROR and no ``summary`` line. So a run
counts as completed only when its exit code is 0..15 AND a ``summary`` line is
present; the exit code alone cannot tell "advisories found" from "failed".

Severity (see ``DIAGNOSTIC_SEVERITY_MAP``): the diagnostic's own ``severity``.
``error`` is HIGH / SARIF ``error``; ``warning`` is MEDIUM / ``warning``; ``note``
is LOW / ``note``; ``help`` is INFO / ``none``. ``error`` is HIGH and not the
CRITICAL ASH's generic ``error`` level maps to, because cargo-deny's severity says
how the project's policy treats the finding, not how exploitable it is: a license
the policy does not allow is also an ``error``. A severity string cargo-deny did
not document is read as HIGH, so nothing is under-reported.

Configuration: cargo-deny reads ``deny.toml`` from its working directory, and a
``deny.toml`` in the scanned repository can ignore advisories, so the tree's file
is NOT read. ``--config`` is always passed: the operator's
``options.config_file`` when set by the operator, else a stub ASH writes that only
holds ``[advisories]`` (cargo-deny's defaults). With that stub the ``licenses``
check rejects every license (no allow-list exists), so ``licenses`` is useful only
with an operator config.

Network and offline: the advisory database is fetched from the RustSec repository
and ``cargo metadata`` may download crate metadata, so the scan needs the network
and the sandbox requests it. ``--offline`` is not used: with no cached database
cargo-deny cannot read advisories. Offline, ``validate_plugin_dependencies``
returns False and the scanner is recorded as missing, like npm-audit.

Dependencies on the host: ``cargo-deny`` AND ``cargo`` (cargo-deny runs
``cargo metadata``). Without a toolchain the run fails and says so.

Installation: cargo-deny is pinned by this module's own installer,
``cargo_deny_install.py`` (version 0.21.0, one release asset per platform for
linux amd64 and arm64, darwin arm64 and windows amd64, with the archive and
executable digests), not by the shared ``utils/tool_downloads.py`` tables, so
construction needs no shared download table. ``ash dependencies install`` places
the verified binary, and the container image runs that install at build time.
``cargo`` is not installed by ASH: a Rust toolchain on PATH stays a prerequisite,
and without one the scanner is reported as missing with that reason.

Location: an advisory is located on the ``Cargo.lock`` beside the manifest, any
other diagnostic on the manifest. cargo-deny's label line numbers refer to
the lockfile or manifest text it parsed but were not verified against the file
for every check, so no line is claimed.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import operator
import os
import re
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import AnyUrl, Field, model_validator

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
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.models.vocab import TargetType
from automated_security_helper.plugin_modules.ash_cargo_deny_plugins.cargo_deny_install import (
    CARGO_DENY_VERSION,
    cargo_deny_install_commands,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    MultiformatMessageString,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.config_trust import operator_path
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: cargo-deny diagnostic severity -> (ASH severity, SARIF level). See the module
#: docstring for why ``error`` is HIGH.
DIAGNOSTIC_SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "bug": ("HIGH", "error"),
    "error": ("HIGH", "error"),
    "warning": ("MEDIUM", "warning"),
    "note": ("LOW", "note"),
    "help": ("INFO", "none"),
}

#: What a severity cargo-deny did not document is rated: the more severe choice.
UNKNOWN_SEVERITY: Tuple[str, str] = DIAGNOSTIC_SEVERITY_MAP["error"]

#: The exit codes a run that completed can have: the bitset of failing checks.
COMPLETED_EXIT_CODES: Set[int] = set(range(16))

CheckName = Literal["advisories", "bans", "licenses", "sources"]

#: What the stub config holds: cargo-deny's own defaults, in a file ASH controls.
STUB_CONFIG = "[advisories]\n"

#: Directory names whose Cargo manifests are build output or vendored copies.
_SKIPPED_DIRS = frozenset({"target"})

#: How much of a failed run's log text goes into an error message.
_EXCERPT_CHARS = 400

_PACKAGE_SPAN = re.compile(r"^(?P<name>\S+) (?P<version>\S+)(?: .*)?$")


class CargoDenyScannerConfigOptions(ScannerOptionsBase):
    checks: Annotated[
        List[CheckName],
        Field(
            description=(
                "The cargo-deny checks to run: advisories, bans, licenses, sources. "
                "advisories is the default. The other three apply the policy in "
                "the config file, so without scanners.cargo-deny.options.config_file "
                "licenses reports every crate's license as not allowed."
            ),
        ),
    ] = ["advisories"]
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a cargo-deny configuration file (deny.toml); a relative "
                "path is taken from the source directory. The file has to be "
                f"outside the scanned tree. {SET_BY_THE_OPERATOR} Set by such a "
                "config, it is ignored with a warning. When it is not used, "
                "cargo-deny gets a stub with its default advisory settings, so a "
                "deny.toml in the scanned repository is not read. A path that is "
                "used and does not exist fails the scan."
            ),
        ),
    ] = None


class CargoDenyScannerConfig(ScannerPluginConfigBase):
    name: Literal["cargo-deny"] = "cargo-deny"
    enabled: bool = True
    options: Annotated[
        CargoDenyScannerConfigOptions, Field(description="Configure cargo-deny")
    ] = CargoDenyScannerConfigOptions()


@ash_scanner_plugin
class CargoDenyScanner(ScannerPluginBase[CargoDenyScannerConfig]):
    """Checks Rust dependencies for advisories and policy violations with cargo-deny."""

    display_name = "cargo-deny"
    docs_summary = "Rust dependency advisories and policy"
    covers = ("Rust (Cargo.lock)",)

    #: cargo-deny is a native binary. See ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False
    # The advisory database is fetched when the scan runs; offline there is no
    # database. validate_plugin_dependencies says no, as npm-audit's does.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    #: The facets register row (base/scanner_facets.py). Declaration only. Native
    #: fields name cargo-deny's own ``--format=json`` diagnostics (captured in
    #: tests/test_data/scanners/cargo-deny/captured/positive.jsonl).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='diagnostic "fields.advisory.id" (RUSTSEC-yyyy-nnnn), '
            'else "fields.code"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='diagnostic "fields.severity" (error, warning, note, help)',
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(none in cargo-deny's JSON) the Cargo.lock beside the "
            "manifest ASH passed on argv for an advisory, the manifest itself for "
            "any other diagnostic (adapter-written)",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason='the native label "line" refers to text cargo-deny parsed and '
            "was not verified against the file, so no line is claimed",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason='the native label "column" is unverified against the file, so '
            "no column is claimed",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='diagnostic "fields.message" with the crate and '
            '"fields.advisory.url" appended',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings are crate and policy diagnostics; a crate name and "
            "version is a package locator, not an infrastructure resource id",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings are crate diagnostics, not deployable resources",
        ),
        package_name=FacetDecl(
            state=FacetState.MAPPED,
            native_field='"fields.advisory.package", else the first label "span" '
            "(<name> <version> <source>)",
        ),
        package_version=FacetDecl(
            state=FacetState.MAPPED,
            native_field='first label "span" (<name> <version> <source>)',
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="the inclusion graph that would give a dependency path is "
            "hidden with --hide-inclusion-graph; no path is read",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.DROPPED,
            native_field='"fields.advisory.aliases" (CVE-yyyy-nnnn and GHSA ids)',
            reason="kept only as the raw aliases property, not mapped to the CVE "
            "taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="RustSec advisories in the captured output carry no CWE field",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["cargo-deny/v1"], a sha256 prefix the '
            "adapter computes over rule, file, crate, version and code (not a "
            "native field: cargo-deny writes no fingerprint)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="the captured advisory object has no patched-versions field; "
            "output not read for one, a sample run would settle it",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the captured diagnostics carry no separate remediation text",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a label span names a crate, not a source snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="rule helpUri https://rustsec.org/advisories/<id> for a "
            'RUSTSEC "fields.advisory.id", the cargo-deny book otherwise '
            "(adapter-written), read into the flat references when the result "
            'carries no relatedLocations; "fields.advisory.url" goes into the '
            'message text and "fields.advisory.references" is not read',
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="rule-level PropertyBag tags cargo-deny, rust and "
            "dependency, written by the adapter, read into the flat tags when the "
            'result carries none; the advisory\'s own "categories" and "keywords" '
            "are discarded",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "cargo_deny_code", "advisory_id", '
            '"aliases", "advisory_kind", "advisory_date" and "issue_severity" '
            "written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py), checked
    #: against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="cargo-deny",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(
                    opsf.Fetched.ADVISORY_FEED,
                    opsf.Fetched.PACKAGE_METADATA,
                ),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "the RustSec advisory database is fetched when the scan runs "
                    "and --offline with no cached database reads no advisories, so "
                    "the scanner does not run offline and is reported as missing"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "cargo_deny_scanner.py offline_strategy, sandbox_requirements "
                    "and validate_plugin_dependencies"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="newline-delimited JSON diagnostics on stderr "
                "(--format=json); cargo-deny's SARIF writer is experimental and "
                "is not used",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection="every Cargo.toml in the scan set with a Cargo.lock "
                "beside it, skipping target/ directories (CargoDenyScanner._manifests)",
                covers_note="declares covers as Rust (Cargo.lock)",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("cargo",),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one cargo-deny run per Cargo project, sharing one "
                "scan_timeout budget",
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for cargo-deny.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(cargo_deny_install.py: linux amd64/arm64, darwin arm64 and "
                "windows amd64), not by the shared tool_downloads table, so the "
                "register lists none; cargo itself is not installed",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the diagnostic's own severity, which says how the policy "
                "treats the finding rather than its exploitability, so error is "
                "HIGH and not CRITICAL",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.OPERATOR,
                        honored=opsf.Honored.YES,
                        surface="deny.toml [advisories] ignore, read only from the "
                        "operator's options.config_file; the scanned tree's "
                        "deny.toml is never read",
                        cite="cargo_deny_scanner.py _resolve_config_file",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="cargo-deny/v1 hash of rule, file, crate, version and code, "
                "so a suppression survives edits to the lockfile elsewhere",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.OPERATOR_PATHS,
                env_prefixes=("CARGO_", "RUSTUP_"),
                options_surface="options.checks (advisories, bans, licenses, "
                "sources) and options.config_file (an operator deny.toml)",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=tuple(sorted(COMPLETED_EXIT_CODES)),
                semantics="a bitset of the checks that reported an error "
                "(advisories 1, bans 2, licenses 4, sources 8); a run completed "
                "only with such a code and a summary line, because a failed run "
                "also exits 1",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_cargo_deny_plugins in ash_plugin_modules",),
                upstream_license=f"MIT OR Apache-2.0 (source: LICENSE-MIT and "
                f"LICENSE-APACHE of the {CARGO_DENY_VERSION} tag's commit, "
                "byte-identical to the copies inside every release archive, read "
                "2026-11-26; no license or service gate, the binary is downloaded "
                "and never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.LOCKFILE, opsf.Prerequisite.MANIFEST),
                note="a Cargo.toml with a Cargo.lock beside it, and a Rust "
                "toolchain on PATH (cargo metadata)",
            ),
        )
    )

    # Any exit code that is a failing-check bitset; a summary line is also required.
    success_exit_codes: ClassVar[Set[int]] = set(COMPLETED_EXIT_CODES)
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        # cargo-deny keeps its advisory database under CARGO_HOME, and cargo keeps
        # its registry there. The toolchain cargo-deny starts is read from
        # RUSTUP_HOME.
        cache_paths=("~/.cargo", "$CARGO_HOME"),
        cache_env=("CARGO_HOME",),
        read_paths=("~/.rustup", "$RUSTUP_HOME"),
        env_prefixes=("CARGO_", "RUSTUP_"),
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CargoDenyScannerConfig()
        self.command = "cargo-deny"
        self.tool_type = ScannerToolType.SCA
        # No base-resolved arguments: scan() builds the whole argv, so nothing
        # from the base resolver can add a token cargo-deny would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "CargoDenyScanner":
        """Install from the pinned release asset in ``cargo_deny_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no cargo-deny entry,
        and building the commands from it raised at construction. This table never
        raises.
        """
        self.custom_install_commands.update(cargo_deny_install_commands())
        return self

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: cargo-deny overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("CargoDenyScanner has no plugin context")
        return self.context

    @property
    def _options(self) -> CargoDenyScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, CargoDenyScannerConfigOptions):
            return options
        return CargoDenyScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _resolve_config_file(self) -> Path:
        """The cargo-deny config to pass with ``--config``; always one.

        Raises:
            ScannerError: when the operator's ``options.config_file`` names a file
                that does not exist. Running with the stub instead would drop the
                policy the operator asked for without saying so in the report.
        """
        source_dir = Path(self._ctx.source_dir)
        configured = self._options.config_file
        if configured is not None and str(configured).strip():
            chosen = operator_path(
                self._ctx.config,
                "scanners.cargo-deny.options.config_file",
                configured,
                source_dir,
            )
            if chosen.path is not None:
                if not chosen.path.is_file():
                    raise ScannerError(
                        f"scanners.cargo-deny.options.config_file is {configured!s}, "
                        f"which does not exist (looked for {chosen.path.as_posix()}). "
                        "Fix the path, or unset it to use cargo-deny's defaults."
                    )
                return chosen.path
            self._plugin_log(
                f"Ignoring scanners.cargo-deny.options.config_file "
                f"({str(configured)!r}): {chosen.refusal}. cargo-deny runs with "
                "its default advisory settings instead.",
                level=logging.WARNING,
            )
        if os.path.lexists(source_dir / "deny.toml"):
            self._plugin_log(
                "deny.toml in the scanned tree is not read: cargo-deny runs with "
                "its default advisory settings. Set "
                "scanners.cargo-deny.options.config_file with --config-overrides or "
                "a config file outside the scanned tree to use a deny.toml.",
                level=logging.INFO,
            )
        stub = Path(self.results_dir or self._ctx.output_dir).joinpath(
            "cargo-deny-default.toml"
        )
        stub.parent.mkdir(parents=True, exist_ok=True)
        with open_for_write(stub) as handle:
            handle.write(STUB_CONFIG)
        return Path(os.path.abspath(stub))

    def _manifests(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """The ``Cargo.toml`` files to run on: those with a ``Cargo.lock`` beside them."""
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        if target_type == TargetType.CONVERTED:
            candidates = list(Path(self._ctx.work_dir).rglob("Cargo.toml"))
        else:
            candidates = [Path(p) for p in scan_set_of(self._ctx)]

        root = Path(target).resolve()
        absolute_output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()
        selected: List[Path] = []
        for path in candidates:
            if path.name != "Cargo.toml":
                continue
            if _SKIPPED_DIRS.intersection(path.parent.parts[len(root.parts) :]):
                continue
            if target_type == TargetType.SOURCE and path.absolute().is_relative_to(
                absolute_output_dir
            ):
                continue
            try:
                if not path.is_file() or not (path.parent / "Cargo.lock").is_file():
                    continue
                resolved = path.resolve()
            except (OSError, RuntimeError):
                continue
            if not resolved.is_relative_to(root):
                self._plugin_log(
                    f"Skipping {path.as_posix()}: it resolves to "
                    f"{resolved.as_posix()}, outside the scanned tree.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
                continue
            if global_ignore_paths and self._ignored(
                path, source_dir, global_ignore_paths
            ):
                continue
            selected.append(path)
        return sorted(set(selected))

    @staticmethod
    def _ignored(
        path: Path, source_dir: Path, global_ignore_paths: List[IgnorePathWithReason]
    ) -> bool:
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        try:
            relative = path.resolve().relative_to(source_dir).as_posix()
        except ValueError:
            relative = path.as_posix()
        return any(
            file_path_matches(relative, ignore_path.path)
            for ignore_path in global_ignore_paths
        )

    def _argv_path(self, path: Path) -> str:
        """How *path* is spelled on the command line, and so in the report.

        Relative to the source directory, which is the subprocess's working
        directory; a path outside it keeps its absolute spelling.
        """
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = path.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    def _argv(self, manifest_arg: str, config_file: Path) -> List[str]:
        return [
            self.command or "cargo-deny",
            f"--manifest-path={manifest_arg}",
            "--locked",
            "--format=json",
            "--log-level=warn",
            "--color=never",
            f"--config={config_file.as_posix()}",
            "check",
            "--hide-inclusion-graph",
            *self._options.checks,
        ]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(self) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="cargo-deny",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://github.com/EmbarkStudios/cargo-deny"
                            ),
                        )
                    ),
                    results=[],
                )
            ],
        )

    def scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CargoDenyScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Run cargo-deny once per Cargo project under *target* and merge the results."""
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Reset above every early return so a second target never inherits counts.
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
            manifests = self._manifests(target, target_type, global_ignore_paths)
            if not manifests:
                self._plugin_log(
                    f"No Cargo.toml with a Cargo.lock beside it found in "
                    f"{target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            config_file = self._resolve_config_file()
            self._plugin_log(
                f"Using cargo-deny config {config_file.as_posix()}",
                target_type=target_type,
                level=logging.INFO,
            )
            self.targets_attempted = len(manifests)

            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("cargo-deny.sarif")
            results_file.unlink(missing_ok=True)

            # One budget for every manifest, so scan_timeout bounds the scanner and
            # not each process.
            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            rules: Dict[str, ReportingDescriptor] = {}
            results: List[Result] = []
            final_args: List[str] = []
            failures: List[str] = []
            run_codes: List[int] = []
            for manifest in manifests:
                manifest_arg = self._argv_path(manifest)
                final_args = self._argv(manifest_arg, config_file)
                # _run_subprocess FOLDS each run's code into self.exit_code (the
                # worst so far), so a failed run's code would otherwise be read
                # as every later run's. Reset it, so what is read after the run
                # is this run's own code.
                self.exit_code = None
                response = self._run_until(final_args, results_dir, deadline)
                exit_code = self.exit_code
                if exit_code is not None:
                    run_codes.append(exit_code)
                if response.get("timed_out"):
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        f"cargo-deny timed out after {timeout}s and was killed, so "
                        "the Cargo projects not yet scanned have no report. Raise "
                        "scanners.cargo-deny.options.scan_timeout if the advisory "
                        "database fetch or the dependency download needs longer."
                    )
                problem = self._completion_problem(response, exit_code)
                if problem is not None:
                    self.targets_failed += 1
                    failures.append(f"{manifest_arg}: {problem}")
                    continue
                converted = convert_cargo_deny_output(
                    response.get("stderr") or "",
                    manifest_uri=manifest_arg,
                    tool_version=self.tool_version,
                )
                rules.update(converted.rules)
                results.extend(converted.results)
            self._post_scan(target=target, target_type=target_type)
            # The scan's recorded code is the bitset of every run's failing checks
            # (a code outside 0..15 is a failed run and kept as it is), so the
            # last run's code does not stand for the scan.
            if run_codes:
                if all(code in COMPLETED_EXIT_CODES for code in run_codes):
                    self.exit_code = functools.reduce(operator.or_, run_codes)
                else:
                    self.exit_code = max(run_codes)

            for failure in failures:
                self.errors.append(failure)
                self._plugin_log(
                    f"cargo-deny did not complete for {failure}",
                    target_type=target_type,
                    level=logging.ERROR,
                    append_to_stream="stderr",
                )
            if self.targets_failed == self.targets_attempted:
                raise ScannerError(
                    "cargo-deny did not complete for any Cargo project: "
                    + "; ".join(failures)
                )

            report = self._empty_report()
            report.runs[0].tool.driver.rules = list(rules.values()) or None
            report.runs[0].results = results
            with open_for_write(results_file) as handle:
                handle.write(
                    report.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            self._inject_invocation(report, final_args, target)
            return report
        except ScannerError:
            raise
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

    def _run_until(
        self, argv: List[str], results_dir: Path, deadline: Optional[float]
    ) -> Dict[str, Any]:
        """Run *argv* with whatever is left of the scan's time budget."""
        if deadline is None:
            remaining = None
        else:
            remaining = deadline - _now()
            if remaining <= 0:
                return {"timed_out": True}
        response = self._run_subprocess(
            command=argv,
            results_dir=results_dir,
            stdout_preference="return",
            stderr_preference="both",
            timeout=remaining,
        )
        return response if isinstance(response, dict) else {}

    @staticmethod
    def _completion_problem(
        response: Dict[str, Any], exit_code: int | None
    ) -> str | None:
        """Why this run did not complete, or None when it did.

        Completed means an exit code that is a failing-check bitset AND a
        ``summary`` line. Log text is quoted only from cargo-deny's own ERROR log
        lines, and truncated.
        """
        if exit_code not in COMPLETED_EXIT_CODES:
            return f"cargo-deny exited {exit_code}, which is not a check result"
        lines = parse_json_lines(response.get("stderr") or "")
        if any(line.get("type") == "summary" for line in lines):
            return None
        logged = [
            str(line.get("fields", {}).get("message", "")).strip()
            for line in lines
            if line.get("type") == "log"
            and str(line.get("fields", {}).get("level", "")).upper() == "ERROR"
        ]
        reason = tool_output_excerpt(" | ".join(m for m in logged if m), _EXCERPT_CHARS)
        return (
            f"cargo-deny exited {exit_code} without a summary, so it did not run its "
            f"checks (is cargo installed, and does the project have a Cargo.lock?)"
            + (f": {reason}" if reason else "")
        )

    def nothing_to_scan_reason(self) -> str | None:
        """None when either tree holds a Cargo.toml with a Cargo.lock beside it.

        The selection ``scan()`` makes, taken without the ignore paths: an ignore
        path only removes manifests, so a tree with none even then has nothing to
        scan, and a tree with one is never reported as having nothing.
        """
        trees: List[TargetType] = [TargetType.SOURCE]
        work_dir = Path(self._ctx.work_dir)
        if work_dir.is_dir() and any(work_dir.rglob("*.*")):
            trees.append(TargetType.CONVERTED)
        for target_type in trees:
            root = Path(
                self._ctx.source_dir if target_type == TargetType.SOURCE else work_dir
            )
            try:
                if self._manifests(root, target_type, []):
                    return None
            except Exception:  # noqa: BLE001 -- cannot tell, so keep MISSING
                return None
        return "no Cargo.toml with a Cargo.lock beside it in the scanned files"

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        if self._scanner_offline():
            self.dependency_unavailable_reason = (
                "cargo-deny reads the advisory database from the network, so it "
                "does not run offline"
            )
            return False
        found = find_executable(self.command or "cargo-deny")
        if not found:
            ASH_LOGGER.warning(
                "cargo-deny executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_cargo_deny_plugins\"]' --tool cargo-deny`."
            )
            return False
        if not find_executable("cargo"):
            self.dependency_unavailable_reason = (
                "cargo not found on PATH; cargo-deny runs `cargo metadata`"
            )
            ASH_LOGGER.warning(
                "cargo not found in PATH; cargo-deny needs a Rust toolchain."
            )
            return False
        return True


#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic


class _Converted:
    def __init__(self) -> None:
        self.rules: Dict[str, ReportingDescriptor] = {}
        self.results: List[Result] = []


def parse_json_lines(text: str) -> List[Dict[str, Any]]:
    """The JSON objects among *text*'s lines; a line that is not one is skipped."""
    out: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, dict):
            out.append(value)
    return out


def _package_of(fields: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """``(name, version)`` of the crate a diagnostic is about, or Nones.

    From the advisory's ``package`` and the first label span
    (``<name> <version> <source>``), since the inclusion graph is hidden.
    """
    advisory = fields.get("advisory")
    name = advisory.get("package") if isinstance(advisory, dict) else None
    version = None
    for label in fields.get("labels") or []:
        span = label.get("span") if isinstance(label, dict) else None
        match = _PACKAGE_SPAN.match(span) if isinstance(span, str) else None
        if match and (name is None or match.group("name") == name):
            name, version = match.group("name"), match.group("version")
            break
    return (name if isinstance(name, str) else None), version


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:32]


def convert_cargo_deny_output(
    stderr: str, *, manifest_uri: str, tool_version: str | None = None
) -> _Converted:
    """Convert one run's JSON lines into SARIF results.

    ``manifest_uri`` is the manifest as spelled on the command line (relative to the
    source directory). An advisory is located on the ``Cargo.lock`` beside it, any
    other diagnostic on the manifest. ``summary`` and ``log`` lines are not findings.
    """
    out = _Converted()
    lock_uri = str(PurePosixPath(manifest_uri).with_name("Cargo.lock"))
    for line in parse_json_lines(stderr):
        if line.get("type") != "diagnostic":
            continue
        fields = line.get("fields")
        if not isinstance(fields, dict):
            continue
        severity, level = DIAGNOSTIC_SEVERITY_MAP.get(
            str(fields.get("severity", "")).lower(), UNKNOWN_SEVERITY
        )
        advisory = fields.get("advisory")
        advisory = advisory if isinstance(advisory, dict) else None
        code = str(fields.get("code") or "")
        rule_id = (
            str(advisory.get("id"))
            if advisory and advisory.get("id")
            else (code or "cargo-deny")
        )
        title = str(fields.get("message") or rule_id)
        name, version = _package_of(fields)
        uri = lock_uri if advisory else manifest_uri
        crate = (
            f" ({name} {version})"
            if name and version
            else (f" ({name})" if name else "")
        )
        text = f"{title}{crate}"
        properties: Dict[str, Any] = {
            "issue_severity": severity,
            "cargo_deny_code": code or None,
            "package_name": name,
            "package_version": version,
        }
        if advisory:
            url = advisory.get("url")
            if url:
                text += f". {url}"
            properties.update(
                advisory_id=advisory.get("id"),
                aliases=[
                    a for a in advisory.get("aliases") or [] if isinstance(a, str)
                ],
                advisory_kind=advisory.get("informational"),
                advisory_date=advisory.get("date"),
            )
        properties = {k: v for k, v in properties.items() if v not in (None, [])}
        description = (advisory or {}).get("title") or title
        out.rules.setdefault(
            rule_id,
            ReportingDescriptor(
                id=rule_id,
                name=rule_id,
                shortDescription=MultiformatMessageString(text=str(description)),
                helpUri=AnyUrl(
                    f"https://rustsec.org/advisories/{rule_id}"
                    if advisory and str(rule_id).startswith("RUSTSEC-")
                    else "https://embarkstudios.github.io/cargo-deny/"
                ),
                properties=PropertyBag(tags=["cargo-deny", "rust", "dependency"]),
            ),
        )
        out.results.append(
            Result.model_validate(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": text},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                    ],
                    "partialFingerprints": {
                        "cargo-deny/v1": _fingerprint(rule_id, uri, name, version, code)
                    },
                    "properties": properties,
                }
            )
        )
    return out


__all__ = [
    "COMPLETED_EXIT_CODES",
    "CargoDenyScanner",
    "CargoDenyScannerConfig",
    "CargoDenyScannerConfigOptions",
    "DIAGNOSTIC_SEVERITY_MAP",
    "convert_cargo_deny_output",
    "parse_json_lines",
]
