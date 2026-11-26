# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CargoAuditScanner: known-vulnerable and flagged crates in Cargo.lock files.

What it runs
------------
``cargo-audit audit --json --file <Cargo.lock>`` once per ``Cargo.lock`` in the scan
set. ``cargo audit`` (RustSec, https://github.com/rustsec/rustsec) compares the
packages a lockfile pins with the RustSec advisory database. It is a Rust software
composition scanner: it reads lockfiles, not source.

Why JSON and not ``--format sarif``
-----------------------------------
cargo-audit's source lists ``--format <terminal|json|sarif>`` and ``--json``. The
JSON report is a serialization of ``rustsec::Report`` (fields ``lockfile``,
``settings``, ``vulnerabilities`` {found, count, list}, ``warnings`` {kind: [..]},
each entry holding ``advisory``, ``package``, ``versions``), which is what this
module reads. The SARIF writer's mapping is the tool's own (every vulnerability is
``error``, every warning ``warning``, all at line 1) and has no ASH severity, so ASH
builds its own SARIF from the JSON and states the mapping below. ``--json`` wins
over ``--format`` and over an ``[output]`` section in a user ``audit.toml``.

Why scan() is overridden
------------------------
The tool writes its report to stdout and has no output-file option, and one run
covers one lockfile, so this plugin uses the own-scan shape (as hadolint does) and
not the template ``_execute_scan`` shape.

Invocation
----------
* ``--file=<absolute path>`` is always passed as one token, so cargo-audit never
  generates a lockfile (which would run ``cargo generate-lockfile`` and reach the
  network for the scanned project) and no path can be read as a flag.
* The working directory is outside the scanned tree. cargo-audit reads
  ``./.cargo/audit.toml`` from it, and a repository's own file could ignore
  advisories; the operator's ``~/.cargo/audit.toml`` still applies. Result URIs
  are source-relative, computed by ASH.

Installation
------------
ASH pins cargo-audit v0.23.0 in this module's own install table
(``cargo_audit_install.py``: one release asset per platform, a SHA256 for each
archive and for the executable inside it), and ``ash dependencies install`` places
it from there. A ``cargo-audit`` already on ``PATH`` is used, so
``cargo install cargo-audit --version 0.23.0 --locked`` works as well.

Severity (``issue_severity`` and the SARIF level agree)
-------------------------------------------------------
* A vulnerability is rated from its advisory's CVSS v3 vector when it carries one
  (>= 9.0 CRITICAL, >= 7.0 HIGH, >= 4.0 MEDIUM, > 0 LOW); an advisory with no
  parsable vector, or a zero score, is HIGH: the tool reports a known vulnerability in a pinned crate
  and ASH does not rate it lower without a score. CRITICAL and HIGH are ``error``,
  MEDIUM is ``warning``, LOW is ``note``.
* Warnings (advisories that are not vulnerabilities): ``unsound`` MEDIUM/warning,
  ``unmaintained`` LOW/note, ``yanked`` LOW/note, ``notice`` LOW/note, any other
  kind LOW/note.

Exit status
-----------
0: nothing found. 1: vulnerabilities found (the report is complete). 2: the run
failed (lockfile unreadable, database missing or unreachable). 0 and 1 succeed; any
other code fails the scan even if text is on stdout.

Network and sandbox
-------------------
Online, cargo-audit fetches the advisory database from GitHub, so the sandbox
requirement asks for a network and the database directory. cargo-audit refuses a
database whose newest commit is more than 90 days old when it fetches
(``Repository::fetch`` with ``ensure_fresh``; ``STALE_AFTER`` in rustsec
``repository/git/commit.rs`` at cargo-audit/v0.23.0), but with ``--no-fetch`` it
opens whatever copy is on disk with no age check (``Auditor::new`` in
``auditor.rs``). ASH holds the content databases it reads offline to a declared age
bound, and the RustSec database is not one of them yet, so the scanner does not run
offline (``OfflineStrategy.SKIP_OFFLINE``) rather than report against a database of
unknown age.
"""

from __future__ import annotations

import json
import logging
import math
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
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
from automated_security_helper.plugin_modules.ash_cargo_audit_plugins.cargo_audit_install import (
    CARGO_AUDIT_VERSION,
    cargo_audit_install_commands,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import tool_output_excerpt
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

LOCKFILE_NAME = "Cargo.lock"

#: Directories never searched for a lockfile: build output and VCS data.
_SKIPPED_DIRS = frozenset({"target", ".git"})

#: warning kind -> (ASH severity, SARIF level). Unknown kinds use ``_DEFAULT_WARNING``.
WARNING_KIND_MAP: Dict[str, Tuple[str, str]] = {
    "unsound": ("MEDIUM", "warning"),
    "unmaintained": ("LOW", "note"),
    "yanked": ("LOW", "note"),
    "notice": ("LOW", "note"),
}
_DEFAULT_WARNING = ("LOW", "note")

#: ASH severity -> SARIF level for a vulnerability.
_LEVEL_FOR_SEVERITY = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_FINGERPRINT_KEY = "cargo-audit/advisory-fingerprint"

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup: the smallest one-decimal number >= *value*."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def cvss3_base_score(vector: Any) -> Optional[float]:
    """The CVSS v3.x base score of *vector*, or None when it is not a v3 vector."""
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        privileges = {
            "N": 0.85,
            "L": 0.68 if scope_changed else 0.62,
            "H": 0.5 if scope_changed else 0.27,
        }[metrics["PR"]]
        exploitability = (
            8.22
            * _CVSS3_WEIGHTS["AV"][metrics["AV"]]
            * _CVSS3_WEIGHTS["AC"][metrics["AC"]]
            * privileges
            * _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        )
        iss = 1 - (
            (1 - _CVSS3_WEIGHTS["C"][metrics["C"]])
            * (1 - _CVSS3_WEIGHTS["I"][metrics["I"]])
            * (1 - _CVSS3_WEIGHTS["A"][metrics["A"]])
        )
    except KeyError:
        return None
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def vulnerability_severity(advisory: Dict[str, Any]) -> str:
    """ASH severity of a vulnerability from its advisory's CVSS vector; HIGH if none."""
    score = cvss3_base_score(advisory.get("cvss"))
    if score is None or score <= 0:
        return "HIGH"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _package(entry: Dict[str, Any]) -> Tuple[str, str]:
    package = entry.get("package")
    if not isinstance(package, dict):
        raise ScannerError("a cargo-audit entry has no package object")
    return str(package.get("name", "?")), str(package.get("version", "?"))


def _result(
    *,
    rule_id: str,
    severity: str,
    level: str,
    text: str,
    uri: str,
    fingerprint: str,
    category: str,
) -> Dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {_FINGERPRINT_KEY: fingerprint},
        "properties": {
            "issue_severity": severity,
            "tags": ["security", "sca", "rust", category],
        },
    }


def convert_cargo_audit_report(document: Any, *, uri: str) -> List[Dict[str, Any]]:
    """SARIF result dicts for one ``cargo audit --json`` document.

    Raises:
        ScannerError: when *document* is not a cargo-audit report.
    """
    if not isinstance(document, dict) or not isinstance(
        document.get("vulnerabilities"), dict
    ):
        raise ScannerError(
            "cargo-audit wrote output that is not a report (no vulnerabilities object)"
        )
    vulnerabilities = document["vulnerabilities"].get("list")
    if not isinstance(vulnerabilities, list):
        raise ScannerError("cargo-audit's report has no vulnerabilities list")
    warnings = document.get("warnings", {})
    if not isinstance(warnings, dict):
        raise ScannerError(
            "cargo-audit's report has a warnings entry that is not an object"
        )

    results: List[Dict[str, Any]] = []
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            raise ScannerError("cargo-audit's report has a malformed vulnerability")
        name, version = _package(entry)
        advisory = entry.get("advisory")
        if not isinstance(advisory, dict) or not advisory.get("id"):
            raise ScannerError("a cargo-audit vulnerability has no advisory id")
        severity = vulnerability_severity(advisory)
        results.append(
            _result(
                rule_id=str(advisory["id"]),
                severity=severity,
                level=_LEVEL_FOR_SEVERITY[severity],
                text=f"{name} {version} is vulnerable to {advisory['id']} "
                f"({advisory.get('title', '')})".replace(" ()", ""),
                uri=uri,
                fingerprint=f"{advisory['id']}:{name}:{version}",
                category="vulnerability",
            )
        )
    for kind, entries in warnings.items():
        if not isinstance(entries, list):
            raise ScannerError("cargo-audit's report has a malformed warning list")
        severity, level = WARNING_KIND_MAP.get(str(kind), _DEFAULT_WARNING)
        for entry in entries:
            if not isinstance(entry, dict):
                raise ScannerError("cargo-audit's report has a malformed warning")
            name, version = _package(entry)
            advisory = entry.get("advisory")
            advisory_id = advisory.get("id") if isinstance(advisory, dict) else None
            title = advisory.get("title") if isinstance(advisory, dict) else None
            text = f"{name} {version} has a {kind} warning"
            if title:
                text += f": {title}"
            results.append(
                _result(
                    rule_id=str(advisory_id or kind),
                    severity=severity,
                    level=level,
                    text=text,
                    uri=uri,
                    fingerprint=f"{advisory_id or kind}:{name}:{version}",
                    category="warning",
                )
            )
    return results


class CargoAuditScannerConfigOptions(ScannerOptionsBase):
    """No options beyond the base ones (``scan_timeout``, ``offline``, severity)."""


class CargoAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["cargo-audit"] = "cargo-audit"
    enabled: bool = True
    options: Annotated[
        CargoAuditScannerConfigOptions,
        Field(description="Configure the cargo-audit scanner"),
    ] = CargoAuditScannerConfigOptions()


@ash_scanner_plugin
class CargoAuditScanner(ScannerPluginBase[CargoAuditScannerConfig]):
    """Rust dependency audit of Cargo.lock files with cargo-audit."""

    python_only: ClassVar[bool | None] = False
    # Online it fetches the advisory database and refuses a stale one. Offline the only
    # copy is the one on disk, which neither cargo-audit (`--no-fetch` skips its age
    # check) nor ASH (no declared content database) holds to an age bound, so the
    # scanner does not run offline. See "Network and sandbox" above.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    # 0: clean, 1: vulnerabilities found. 2 means the run failed.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}
    # The advisory database is fetched into ~/.cargo/advisory-db. Not granted
    # network access under --offline.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=("~/.cargo/advisory-db",),
    )

    #: The facets register row (base/scanner_facets.py). The native fields name
    #: the rustsec ``Report`` JSON (``cargo audit --json``) that this adapter
    #: converts to SARIF; the adapter writes the SARIF, so a mapped cell that
    #: is not a native field says what the adapter derives it from.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field="vulnerabilities.list[].advisory.id and "
            "warnings.<kind>[].advisory.id (the warning kind when a warning "
            "has no advisory)",
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="advisory.cvss (a CVSS v3 vector the adapter scores); "
            "warnings use the warning kind",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(none) the Cargo.lock the run was given, "
            "source-relative, written by the adapter",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(none) the report carries no lockfile positions; the "
            "adapter writes startLine 1",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="a lockfile advisory has no column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="package.name, package.version and advisory.title, "
            "assembled into the result text by the adapter",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="findings name a crate and version in a lockfile, not a "
            "deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings name a crate and version in a lockfile, not a "
            "deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.DROPPED,
            native_field="package.name",
            reason="the adapter writes the crate into the message and the "
            "fingerprint only, not into the package properties",
        ),
        package_version=FacetDecl(
            state=FacetState.DROPPED,
            native_field="package.version",
            reason="the adapter writes the version into the message and the "
            "fingerprint only, not into the package properties",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it (the JSON "
            "report's dependency path is unread)",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.DROPPED,
            native_field="advisory.aliases",
            reason="RustSec advisories list CVE and GHSA aliases; the adapter "
            "does not write them",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="output not read; a sample run would settle it",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field="partialFingerprints[cargo-audit/advisory-fingerprint], "
            "advisory id, crate and version joined by the adapter",
        ),
        fix_available=FacetDecl(
            state=FacetState.DROPPED,
            native_field="versions.patched",
            reason="the adapter does not read the patched version ranges",
        ),
        remediation_text=FacetDecl(
            state=FacetState.DROPPED,
            native_field="versions.patched",
            reason="the adapter writes no upgrade text from the patched ranges",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a lockfile finding has no source snippet",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field="advisory.url",
            reason="the adapter writes no advisory link",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="properties.tags security, sca, rust and "
            "vulnerability or warning, written by the adapter",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="properties.issue_severity, written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="cargo-audit",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.ADVISORY_FEED,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "offline, the only RustSec database is the copy in "
                    "~/.cargo/advisory-db, which --no-fetch opens with no age check "
                    "and ASH declares no content-database bound for, so the "
                    "scanner is skipped"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source="cargo_audit_scanner.py offline_strategy, "
                "validate_plugin_dependencies and sandbox_requirements; module "
                "header (Network and sandbox)",
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection="every Cargo.lock in the scan set, outside target/ "
                "build trees (_lockfiles)",
                covers_note="a community scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("cargo-audit",),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one cargo-audit run per Cargo.lock",
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for cargo-audit.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(cargo_audit_install.py: linux, darwin amd64/arm64 and "
                "windows/amd64), not by the shared tool_downloads table, so the "
                "register lists none",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="a vulnerability is rated from its advisory's CVSS v3 "
                "vector (HIGH without one); a warning from its kind",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="./.cargo/audit.toml in the tool's working "
                        "directory (advisories.ignore)",
                        cite="cargo-audit config.rs AuditConfig::load reads "
                        "./.cargo/audit.toml; _subprocess_cwd runs the tool "
                        "outside the scanned tree",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.OPERATOR,
                        honored=opsf.Honored.YES,
                        surface="~/.cargo/audit.toml in the operator's home",
                        cite="cargo-audit config.rs AuditConfig::load",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="advisory id, crate and version under "
                "cargo-audit/advisory-fingerprint",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="the base options only; the advisories are RustSec's",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 clean, 1 vulnerabilities found (report complete), "
                "any other code is a failed run",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=("ash_cargo_audit_plugins in ash_plugin_modules",),
                upstream_license="Apache-2.0 OR MIT (source: the license field of "
                "cargo-audit/Cargo.toml and the LICENSE-APACHE and LICENSE-MIT files "
                f"at the {CARGO_AUDIT_VERSION} tag commit e3cf3703, which the linux "
                "and macOS release archives carry byte for byte, read 2026-11-26; no "
                "license or service gate, the binary is downloaded and never "
                "vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.LOCKFILE,),
                note="a Cargo.lock; the tool never generates one (--file is "
                "always passed)",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CargoAuditScannerConfig()
        self.command = "cargo-audit"
        self.subcommands = ["audit"]
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "CargoAuditScanner":
        """Install from the pinned release asset in ``cargo_audit_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no cargo-audit entry,
        and building the commands from it raised at construction. This table never
        raises.
        """
        self.custom_install_commands.update(cargo_audit_install_commands())
        return self

    def nothing_to_scan_reason(self) -> str | None:
        """None when either tree holds a Cargo.lock outside a build directory."""
        trees: List[Literal["source", "converted"]] = ["source"]
        work_dir = Path(self._ctx.work_dir)
        if work_dir.is_dir() and any(work_dir.rglob("*.*")):
            trees.append("converted")
        for target_type in trees:
            root = (
                work_dir if target_type == "converted" else Path(self._ctx.source_dir)
            )
            try:
                if self._lockfiles(root, target_type, []):
                    return None
            except OSError:
                return None
        return f"no {LOCKFILE_NAME} in the scanned files"

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: cargo-audit overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover
            raise ScannerError("CargoAuditScanner has no plugin context")
        return self.context

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _lockfiles(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """The ``Cargo.lock`` files under *target*, sorted.

        Source: ASH's scan set (ignore files already applied). Converted: the work
        directory. Files in ``target/`` build trees and ASH's output directory are
        dropped, and a link that resolves outside the tree is skipped, so text
        from outside the scanned tree never reaches the tool.
        """
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        if target_type == "converted":
            candidates = list(Path(self._ctx.work_dir).rglob(LOCKFILE_NAME))
        else:
            candidates = [Path(p) for p in scan_set_of(self._ctx)]
        root = Path(target).resolve()
        output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()
        selected: List[Path] = []
        for path in candidates:
            if path.name != LOCKFILE_NAME:
                continue
            if _SKIPPED_DIRS.intersection(path.parts[:-1]):
                continue
            if target_type == "source" and path.absolute().is_relative_to(output_dir):
                continue
            try:
                if not path.is_file():
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
        """*path* relative to the source directory (the working directory)."""
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = path.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    def _argv(self, lockfile: Path) -> List[str]:
        """The command line for one lockfile.

        The lockfile travels as one ``--file=<absolute path>`` token, so no path
        can be read as a flag. The tool runs outside the scanned tree
        (``_subprocess_cwd``), hence the absolute path. There is no ``--no-fetch``:
        an offline scan never gets here (``validate_plugin_dependencies``).
        """
        return [
            self.command or "cargo-audit",
            "audit",
            "--json",
            f"--file={lockfile.absolute().as_posix()}",
        ]

    def _subprocess_cwd(self, results_dir: Path) -> Path | None:
        """A working directory outside the scanned tree.

        cargo-audit reads ``./.cargo/audit.toml`` from its working directory
        (cargo-audit ``config.rs``, ``AuditConfig::load``) and a project file
        there outranks the operator's ``~/.cargo/audit.toml``. A repository
        could therefore list its own advisories under ``ignore`` or point the
        database at its own path. It has no ``--config`` flag, so the run starts
        where the scanned tree has no say.
        """
        from automated_security_helper.config.path_trust import (
            cwd_outside_scanned_tree,
        )

        return cwd_outside_scanned_tree(
            self._ctx.source_dir,
            results_dir=results_dir,
            source_dir=self._ctx.source_dir,
            config=getattr(self._ctx, "config", None),
        )

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(self) -> SarifReport:
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "cargo-audit",
                                "informationUri": "https://github.com/rustsec/rustsec",
                            }
                        },
                        "results": [],
                    }
                ],
            }
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CargoAuditScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Audit every Cargo.lock under *target* (one cargo-audit run each)."""
        if global_ignore_paths is None:
            global_ignore_paths = []
        self.targets_attempted = 0
        self.targets_failed = 0

        if self._target_is_empty(target):
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
            lockfiles = self._lockfiles(target, target_type, global_ignore_paths)
            if not lockfiles:
                self._plugin_log(
                    f"No {LOCKFILE_NAME} found in {target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            self.targets_attempted = len(lockfiles)
            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("cargo-audit.sarif")
            results_file.unlink(missing_ok=True)

            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else time.monotonic() + timeout

            collected: List[Dict[str, Any]] = []
            final_args: List[str] = []
            responses: List[Tuple[Path, Dict[str, Any], Optional[int]]] = []
            for lockfile in lockfiles:
                final_args = self._argv(lockfile)
                response = self._run_until(final_args, results_dir, deadline)
                responses.append((lockfile, response, self.exit_code))
                if response.get("timed_out") or self.exit_code not in (
                    self.success_exit_codes
                ):
                    break
            self._post_scan(target=target, target_type=target_type)

            for lockfile, response, exit_code in responses:
                self.exit_code = exit_code
                self._check_response(response, timeout, lockfile)
                collected.extend(
                    convert_cargo_audit_report(
                        self._parse_json(response, lockfile),
                        uri=self._argv_path(lockfile),
                    )
                )

            report = self._empty_report()
            run = report.runs[0]
            run.results = (
                SarifReport.model_validate(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "cargo-audit"}},
                                "results": collected,
                            }
                        ],
                    }
                )
                .runs[0]
                .results
            )
            with open_for_write(results_file) as handle:
                handle.write(
                    report.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            self._inject_invocation(report, final_args, target)
            return report
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

    def _run_until(
        self, argv: List[str], results_dir: Path, deadline: Optional[float]
    ) -> Dict[str, Any]:
        """Run *argv* with whatever is left of the scan's time budget."""
        if deadline is None:
            remaining = None
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {"timed_out": True}
        response = self._run_subprocess(
            command=argv,
            results_dir=results_dir,
            stdout_preference="return",
            stderr_preference="both",
            cwd=self._subprocess_cwd(results_dir),
            env=dict(snapshot_environ()),
            timeout=remaining,
        )
        return response if isinstance(response, dict) else {}

    def _check_response(
        self, response: Dict[str, Any], timeout: Optional[float], lockfile: Path
    ) -> None:
        if response.get("timed_out"):
            raise ScannerError(
                f"cargo-audit timed out after {timeout}s and was killed, so it "
                "produced no report. Raise scanners.cargo-audit.options.scan_timeout "
                "if the advisory database fetch legitimately needs longer."
            )
        if self.exit_code not in self.success_exit_codes:
            stderr = (response.get("stderr") or "").strip()
            raise ScannerError(
                f"cargo-audit exited {self.exit_code} on {self._argv_path(lockfile)}, "
                "so it did not complete"
                + (f": {tool_output_excerpt(stderr, 500)}" if stderr else "")
            )

    @staticmethod
    def _parse_json(response: Dict[str, Any], lockfile: Path) -> Any:
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            raise ScannerError(f"cargo-audit wrote no report for {lockfile.name}")
        try:
            return json.loads(stdout)
        except ValueError as e:
            raise ScannerError(f"cargo-audit's output is not JSON ({type(e).__name__})")

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        if self._scanner_offline():
            # SKIP_OFFLINE: the database on disk would be read with no age bound.
            self.dependency_unavailable_reason = (
                "cargo-audit does not run offline: with --no-fetch it reads the "
                "RustSec database in ~/.cargo/advisory-db with no age check, and ASH "
                "holds no age bound for that database, so a stale copy would read as "
                "a clean scan. Run it online."
            )
            self._plugin_log(
                f"Offline mode detected. Skipping {self.__class__.__name__}: its "
                "advisory database cannot be held to an age bound offline."
            )
            return False
        found = find_executable(self.command or "cargo-audit")
        if not found:
            ASH_LOGGER.warning(
                "cargo-audit executable not found in PATH. Install the pinned "
                f"release ({CARGO_AUDIT_VERSION}) with `ash dependencies install "
                "--config-overrides 'ash_plugin_modules+=[\"automated_security_helper."
                "plugin_modules.ash_cargo_audit_plugins\"]' --tool cargo-audit`, or "
                "build it with `cargo install cargo-audit --version "
                f"{CARGO_AUDIT_VERSION.lstrip('v')} --locked`."
            )
        return found is not None


__all__ = [
    "CargoAuditScanner",
    "CargoAuditScannerConfig",
    "CargoAuditScannerConfigOptions",
    "WARNING_KIND_MAP",
    "convert_cargo_audit_report",
    "cvss3_base_score",
    "vulnerability_severity",
]
