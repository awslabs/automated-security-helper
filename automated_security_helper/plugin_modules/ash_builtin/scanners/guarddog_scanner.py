# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GuardDog: malicious-package heuristics for the packages in a repository.

GuardDog (https://github.com/DataDog/guarddog, Apache-2.0) runs YARA rules that
look for the shapes malicious packages take -- an install hook that downloads and
executes, ``exec`` of a base64-decoded payload, exfiltration to a raw IP -- and
correlates them into "risks" with a severity.

What ASH runs
-------------
``guarddog <ecosystem> scan <dir>`` once per package root ASH finds in the
target, for each enabled ecosystem. A package root is a directory holding one of
that ecosystem's manifests (``_PACKAGE_MANIFESTS``). This is GuardDog's local
source mode: it reads files and needs no network.

``guarddog <ecosystem> verify <manifest>`` is GuardDog's dependency mode: it
downloads every dependency the manifest names from its registry and scans each
one. It needs the network, can take a long time, and is therefore off unless
``options.verify`` is true. Under ``ASH_OFFLINE`` it is not attempted: each
manifest it would have read is a failed target, and the scanner reports ERROR
naming the reason. It is also bounded by ``options.verify_timeout``.

Why ASH stages each package root before scanning it
---------------------------------------------------
GuardDog walks the whole directory it is given, with no exclusion option: a root
``package.json`` would have it read every file under ``node_modules/``, once per
rule. So ASH builds a staging tree per package root holding only the files ASH
would scan -- the scan set (``.gitignore``, ``.ashignore``), less
``KNOWN_IGNORE_PATHS``, ``global_settings.ignore_paths``,
``options.excluded_paths``, ASH's output directory and any nested package root of
the same ecosystem (scanned on its own). Files are hard-linked when the staging
directory is on the same filesystem and copied otherwise. Symlinks are never
staged, which keeps GuardDog from reading anything outside the target.

Why the result is converted from JSON rather than read as SARIF
---------------------------------------------------------------
GuardDog 3.x offers ``--output-format sarif`` only for ``verify``; ``scan``
offers JSON alone. Its SARIF also gives every rule the same level ("warning"),
which carries no severity at all. The JSON carries GuardDog's own risk
correlation, so both modes are read as JSON and converted here; the severity
mapping is ``_risk_severity`` and the table in the plugin docs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Literal,
    Tuple,
    cast,
)

from pydantic import Field, field_validator, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.package_identity import identity_properties
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command

#: The GuardDog release this parser was written and tested against. Exact rather
#: than a range on purpose: the JSON this module reads is not a documented,
#: versioned format, and 3.x has reshaped it between minor releases (3.0 removed
#: SARIF from ``scan``; 3.1 added ``risks``). ``options.tool_version`` overrides it.
GUARDDOG_DEFAULT_VERSION_CONSTRAINT = "==3.2.0"

#: Interpreters GuardDog 3.2.0 can be installed into from wheels alone. pygit2
#: 1.18 and yara-python 4.5 publish no CPython 3.14 wheels, so on a host where uv
#: would pick 3.14 the install falls back to building them from source, which
#: needs libgit2 headers and a C toolchain, and fails. Measured with uv 0.12 on
#: Linux x86_64: an unconstrained ``uv tool install guarddog==3.2.0`` picked
#: 3.14 and failed on pygit2; with ``--python '>=3.10,<3.14'`` it installed.
GUARDDOG_PYTHON_REQUEST = ">=3.10,<3.14"

_COMMAND = "guarddog"

GuardDogEcosystem = Literal["pypi", "npm", "go", "github_action", "rubygems", "crates"]

#: Every ecosystem ASH can drive at the pinned GuardDog version, in CLI spelling.
#: GuardDog's ``extension`` ecosystem (editor extensions) is not offered: its
#: manifest is an ordinary package.json and cannot be told apart from npm's.
GUARDDOG_ECOSYSTEMS: Tuple[GuardDogEcosystem, ...] = (
    "pypi",
    "npm",
    "go",
    "github_action",
    "rubygems",
    "crates",
)

#: Files that make a directory a package root, per ecosystem, for ``scan``.
_PACKAGE_MANIFESTS: Dict[str, Tuple[str, ...]] = {
    "pypi": ("setup.py", "setup.cfg", "pyproject.toml"),
    "npm": ("package.json",),
    "go": ("go.mod",),
    "github_action": ("action.yml", "action.yaml"),
    "rubygems": (),  # any *.gemspec, see _is_package_manifest
    "crates": ("Cargo.toml",),
}

#: The dependency manifests each ecosystem's ``verify`` reads, matching the
#: ``find_requirements`` of GuardDog's project scanners at the pinned version.
_PYPI_REQUIREMENTS = re.compile(r"^requirements(-dev)?\.txt$", re.IGNORECASE)
_VERIFY_MANIFESTS: Dict[str, Tuple[str, ...]] = {
    "npm": ("package.json",),
    "go": ("go.mod",),
    "rubygems": ("Gemfile.lock",),
    "crates": ("Cargo.lock",),
}

#: GuardDog's metadata rules at the pinned version (``analyzer/metadata``). They
#: read registry metadata, which a local ``scan`` of a directory does not have, so a
#: ``rules`` selection made only of these checks nothing there. Used for a warning.
_METADATA_ONLY_HINT = frozenset(
    {
        "bundled_binary",
        "deceptive_author",
        "direct_url_dependency",
        "metadata_mismatch",
        "potentially_compromised_email_domain",
        "provenance_regression",
        "repository_integrity_mismatch",
        "risky_new_dependency",
        "typosquatting",
        "unclaimed_maintainer_email_domain",
    }
)

#: Rule names as GuardDog spells them. Checked before they reach argv so a
#: configured value can never be read as an option (``--metadata=...``).
_RULE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

#: GuardDog's own wording when its kernel sandbox (nono) cannot be applied.
_SANDBOX_UNAVAILABLE_MARKER = "Kernel-level sandbox is not available"

#: GuardDog's stderr prefix for an error it logged and then carried on past --
#: notably a registry lookup that failed during ``verify``, after which it prints
#: ``[]`` and exits 0, which would otherwise read as "no dependencies, no findings".
_GUARDDOG_ERROR_LINE = re.compile(r"^ERROR:", re.MULTILINE)

_SEVERITY_LEVELS = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


def _risk_severity(value: Any) -> str:
    """ASH severity for a GuardDog risk severity (``high``/``medium``/``low``).

    GuardDog derives a risk's severity from the matching threat rule's own
    ``severity`` metadata, lowered one band when the capability it was paired
    with sits in another file and two bands when it is in another category. That
    is GuardDog's judgment of how bad the correlated finding is, so it is used
    one-to-one. An unrecognized value is MEDIUM: it is still a correlated risk,
    and reporting it below the default threshold would hide it.
    """
    text = str(value or "").strip().lower()
    return {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(text, "MEDIUM")


def _is_package_manifest(ecosystem: str, filename: str) -> bool:
    if ecosystem == "rubygems":
        return filename.endswith(".gemspec")
    return filename in _PACKAGE_MANIFESTS.get(ecosystem, ())


def _is_verify_manifest(ecosystem: str, rel_posix: str) -> bool:
    name = rel_posix.rsplit("/", 1)[-1]
    if ecosystem == "pypi":
        return bool(_PYPI_REQUIREMENTS.match(name))
    if ecosystem == "github_action":
        parent = rel_posix.rsplit("/", 1)[0] if "/" in rel_posix else ""
        return (
            parent == ".github/workflows" or parent.endswith("/.github/workflows")
        ) and name.endswith((".yml", ".yaml"))
    return name in _VERIFY_MANIFESTS.get(ecosystem, ())


def _split_location(location: Any) -> Tuple[str | None, int | None]:
    """``"pkg/setup.py:16"`` -> ``("pkg/setup.py", 16)``; tolerant of a bare path."""
    if not isinstance(location, str) or not location:
        return None, None
    path, sep, line = location.rpartition(":")
    if sep and line.isdigit():
        return path, int(line)
    return location, None


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256(
        "\x1f".join(str(p) for p in parts).encode("utf-8")
    ).hexdigest()


class GuardDogScannerConfigOptions(ScannerOptionsBase):
    ecosystems: Annotated[
        List[GuardDogEcosystem],
        Field(
            description=(
                "GuardDog ecosystems to scan. ASH scans every package root of each "
                "ecosystem it finds: pypi (setup.py, setup.cfg, pyproject.toml), npm "
                "(package.json), go (go.mod), github_action (action.yml, action.yaml), "
                "rubygems (*.gemspec) and crates (Cargo.toml)."
            )
        ),
    ] = list(GUARDDOG_ECOSYSTEMS)
    verify: Annotated[
        bool,
        Field(
            description=(
                "Also run `guarddog <ecosystem> verify` on dependency manifests "
                "(requirements.txt, package.json, go.mod, Gemfile.lock, Cargo.lock, "
                "GitHub workflow files). This downloads every dependency from its "
                "registry and needs network access; with ASH_OFFLINE set the scanner "
                "reports ERROR instead of attempting it."
            )
        ),
    ] = False
    verify_timeout: Annotated[
        int,
        Field(
            description=(
                "Seconds to allow one `guarddog verify` invocation (one manifest) "
                "before it is killed and reported as a failed target."
            ),
            ge=1,
        ),
    ] = 600
    verify_parallelism: Annotated[
        int,
        Field(
            description=(
                "Dependencies `guarddog verify` downloads concurrently "
                "(GUARDDOG_PARALLELISM). GuardDog's own default is the CPU count."
            ),
            ge=1,
            le=64,
        ),
    ] = 8
    sandbox: Annotated[
        Literal["auto", "required", "disabled"],
        Field(
            description=(
                "GuardDog's kernel sandbox for `scan` (nono: Landlock on Linux, "
                "Seatbelt on macOS), which blocks network access and limits reads to "
                "the scanned directory. `auto` uses it where the platform supports it "
                "and otherwise scans without it, logging a warning; `required` reports "
                "ERROR where it is unavailable; `disabled` never uses it."
            )
        ),
    ] = "auto"
    rules: Annotated[
        List[str],
        Field(
            description=(
                "Run only these GuardDog rules (`--rules`). Cannot be combined with "
                "exclude_rules. Empty runs every rule."
            )
        ),
    ] = []
    exclude_rules: Annotated[
        List[str],
        Field(description="GuardDog rules to skip (`--exclude-rules`)."),
    ] = []
    include_capabilities: Annotated[
        bool,
        Field(
            description=(
                "Also report GuardDog capability matches (capability-* rules, e.g. "
                "'spawns a process') that GuardDog did not correlate into a risk, at "
                "INFO severity. They are context rather than findings: ordinary code "
                "matches them."
            )
        ),
    ] = False
    excluded_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description=(
                "Paths (globs relative to the source directory) to leave out of the "
                "files GuardDog is given."
            )
        ),
    ] = []
    tool_version: Annotated[
        str | None,
        Field(
            description=(
                "Version constraint for guarddog installation, in pip requirement "
                "syntax. Leave unset to use the scanner's own default constraint, "
                "which is the GuardDog release the result parser is tested against."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300

    @field_validator("rules", "exclude_rules")
    @classmethod
    def _rule_names_are_names(cls, value: List[str]) -> List[str]:
        for item in value:
            if not isinstance(item, str) or not _RULE_NAME.match(item):
                raise ValueError(
                    f"{item!r} is not a GuardDog rule name: expected lowercase "
                    "letters, digits, '-' and '_', for example "
                    "'threat-runtime-obfuscation-base64exec'"
                )
        return value

    @model_validator(mode="after")
    def _rules_xor_exclude_rules(self) -> "GuardDogScannerConfigOptions":
        if self.rules and self.exclude_rules:
            raise ValueError(
                "rules and exclude_rules cannot both be set: GuardDog rejects "
                "--rules together with --exclude-rules"
            )
        return self


class GuardDogScannerConfig(ScannerPluginConfigBase):
    name: Literal["guarddog"] = "guarddog"
    # Opt-in: see GuardDogScanner.OPT_IN.
    enabled: bool = False
    options: Annotated[
        GuardDogScannerConfigOptions, Field(description="Configure GuardDog scanner")
    ] = GuardDogScannerConfigOptions()


@dataclass
class _Target:
    """One GuardDog invocation: a package root to scan or a manifest to verify."""

    mode: Literal["scan", "verify"]
    ecosystem: str
    path: Path  # package root (scan) or manifest file (verify), absolute
    label: str  # path relative to the source dir, for messages and URIs


@dataclass
class _Converted:
    results: List[Result] = field(default_factory=list)
    rules: Dict[str, ReportingDescriptor] = field(default_factory=dict)
    #: Per result, in the same order: the identity used to report a finding
    #: once across invocations, and its ASH severity. Kept beside the SARIF
    #: model rather than read back out of it, where every field is optional.
    keys: List[Tuple[Any, ...]] = field(default_factory=list)
    severities: List[str] = field(default_factory=list)

    def take(self, made: "Tuple[Result, Tuple[Any, ...], str]") -> None:
        result, key, severity = made
        self.results.append(result)
        self.keys.append(key)
        self.severities.append(severity)


def _rule_descriptor(rule_id: str, description: str | None) -> ReportingDescriptor:
    text = description or f"GuardDog rule {rule_id}"
    return ReportingDescriptor.model_validate(
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": text},
            "fullDescription": {"text": text},
            "helpUri": "https://github.com/DataDog/guarddog#heuristics",
            "properties": {"tags": ["guarddog", "malicious-package"]},
        }
    )


def _make_result(
    *,
    rule_id: str,
    severity: str,
    message: str,
    uri: str,
    line: int | None,
    snippet: str | None,
    extra_properties: Dict[str, Any],
    fingerprint_parts: Iterable[Any],
) -> Tuple[Result, Tuple[Any, ...], str]:
    """A SARIF result, its de-duplication key and its ASH severity."""
    physical: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
    if line is not None and line > 0:
        region: Dict[str, Any] = {"startLine": line}
        if snippet:
            region["snippet"] = {"text": snippet}
        physical["region"] = region
    result = Result.model_validate(
        {
            "ruleId": rule_id,
            "level": _SEVERITY_LEVELS[severity],
            "message": {"text": message},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {"guarddog/v1": _fingerprint(*fingerprint_parts)},
            "properties": {"issue_severity": severity, **extra_properties},
        }
    )
    key = (
        rule_id,
        uri,
        line,
        snippet,
        extra_properties.get("package_name"),
        extra_properties.get("package_version"),
    )
    return result, key, severity


def convert_guarddog_scan_result(
    document: Dict[str, Any],
    *,
    uri_prefix: str,
    ecosystem: str,
    include_capabilities: bool = False,
    dependency: Tuple[str, str | None] | None = None,
    manifest_uri: str | None = None,
    manifest_line: int | None = None,
) -> _Converted:
    """Convert one GuardDog ``scan`` JSON document into SARIF results.

    ``document`` is what ``guarddog <eco> scan <dir> --output-format json``
    prints, or one entry's ``result`` from ``verify``. Locations GuardDog
    reports are relative to the directory it scanned; ``uri_prefix`` (a posix
    path relative to the source directory, ``""`` for the source directory
    itself) is prepended to place them in the repository.

    For a ``verify`` entry, ``dependency`` is ``(name, version)`` and the
    finding is located on the manifest line that declares it
    (``manifest_uri``/``manifest_line``): the file GuardDog matched lives in
    the downloaded package, not in the repository, so it goes in the message.

    Severity, in order of precedence:

    1. A source-code match GuardDog correlated into a risk takes the risk's
       severity (``_risk_severity``).
    2. A ``threat-*`` match GuardDog did not correlate is LOW. GuardDog found the
       pattern but its own engine did not treat it as a risk.
    3. A metadata rule (typosquatting, compromised maintainer domain, ...) that
       fired is MEDIUM. GuardDog gives those no severity.
    4. A ``capability-*`` match not used by any risk is INFO, and only reported
       when ``include_capabilities`` is set.
    """
    out = _Converted()
    results_by_rule = document.get("results") or {}
    if not isinstance(results_by_rule, dict):
        results_by_rule = {}

    def place(rel: str | None) -> str:
        rel = (rel or "").replace("\\", "/").lstrip("/")
        if not uri_prefix:
            return rel
        return f"{uri_prefix.rstrip('/')}/{rel}" if rel else uri_prefix

    dep_props: Dict[str, Any] = {"guarddog_ecosystem": ecosystem}
    dep_text = ""
    if dependency is not None:
        dep_name, dep_version = dependency
        dep_props.update(identity_properties(dep_name, dep_version, None))
        dep_text = f"Dependency {dep_name}{f' {dep_version}' if dep_version else ''}: "

    def location_for(file_rel: str | None, line: int | None) -> Tuple[str, int | None]:
        if dependency is not None and manifest_uri is not None:
            return manifest_uri, manifest_line
        return place(file_rel), line

    def where(file_rel: str | None, line: int | None) -> str:
        if dependency is None or not file_rel:
            return ""
        return f" (in the package's {file_rel}{f':{line}' if line else ''})"

    consumed: set[tuple[Any, Any, Any]] = set()

    # 1. Risks: correlated threat (+ capability) pairs, with GuardDog's severity.
    for risk in document.get("risks") or []:
        if not isinstance(risk, dict):
            continue
        rule_id = str(risk.get("threat_rule") or risk.get("name") or "guarddog-risk")
        file_rel, line = _split_location(risk.get("threat_location"))
        if file_rel is None:
            file_rel = risk.get("file_path")
        severity = _risk_severity(risk.get("severity"))
        description = risk.get("threat_description") or None
        out.rules.setdefault(rule_id, _rule_descriptor(rule_id, description))
        capability = risk.get("capability_rule")
        tactics = [t for t in risk.get("mitre_tactics") or [] if isinstance(t, str)]
        text = f"{dep_text}{description or rule_id}{where(file_rel, line)}"
        if capability:
            text += f"; correlated with capability {capability}"
        if tactics:
            text += f". MITRE ATT&CK tactics: {', '.join(tactics)}"
        uri, out_line = location_for(file_rel, line)
        out.take(
            _make_result(
                rule_id=rule_id,
                severity=severity,
                message=text,
                uri=uri,
                line=out_line,
                snippet=risk.get("threat_code") or None,
                extra_properties={
                    **dep_props,
                    "guarddog_risk": risk.get("name"),
                    "guarddog_risk_severity": risk.get("severity"),
                    "guarddog_capability_rule": capability,
                    "guarddog_match": risk.get("threat_match"),
                    "mitre_tactics": tactics,
                },
                fingerprint_parts=(
                    rule_id,
                    uri,
                    out_line,
                    file_rel,
                    line,
                    risk.get("threat_match"),
                ),
            )
        )
        consumed.add((rule_id, risk.get("threat_location"), risk.get("threat_code")))

    # 2-4. Matches GuardDog's risk engine did not use, and metadata rules.
    for rule_id, hits in sorted(results_by_rule.items()):
        if not hits:
            continue
        if isinstance(hits, str):
            # A metadata rule: GuardDog reports its finding as one message.
            out.rules.setdefault(rule_id, _rule_descriptor(rule_id, None))
            uri, out_line = location_for(None, None)
            if dependency is None:
                uri, out_line = manifest_uri or place(None), manifest_line
            out.take(
                _make_result(
                    rule_id=rule_id,
                    severity="MEDIUM",
                    message=f"{dep_text}{hits}",
                    uri=uri,
                    line=out_line,
                    snippet=None,
                    extra_properties=dep_props,
                    fingerprint_parts=(rule_id, uri, out_line, hits),
                )
            )
            continue
        if isinstance(hits, dict):
            # Metadata rules that did not fire come back as {} or null; anything
            # else in dict form is not a shape this version emits.
            continue
        if not isinstance(hits, list):
            continue
        is_capability = rule_id.startswith("capability-")
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            file_rel, line = _split_location(hit.get("location"))
            if is_capability:
                if not include_capabilities:
                    continue
                severity = "INFO"
            else:
                if (rule_id, hit.get("location"), hit.get("code")) in consumed:
                    continue
                severity = "LOW"
            message = hit.get("message") or rule_id
            out.rules.setdefault(rule_id, _rule_descriptor(rule_id, message))
            qualifier = (
                " (capability; not correlated into a risk by GuardDog)"
                if is_capability
                else " (not correlated into a risk by GuardDog)"
            )
            uri, out_line = location_for(file_rel, line)
            out.take(
                _make_result(
                    rule_id=rule_id,
                    severity=severity,
                    message=f"{dep_text}{message}{where(file_rel, line)}{qualifier}",
                    uri=uri,
                    line=out_line,
                    snippet=hit.get("code") or None,
                    extra_properties={**dep_props, "guarddog_match": hit.get("match")},
                    fingerprint_parts=(
                        rule_id,
                        uri,
                        out_line,
                        file_rel,
                        line,
                        hit.get("match"),
                    ),
                )
            )
    return out


def guarddog_errors(document: Dict[str, Any]) -> Dict[str, str]:
    """The per-rule or per-step errors GuardDog recorded in one result document."""
    errors = document.get("errors") or {}
    if not isinstance(errors, dict):
        return {"guarddog": str(errors)}
    return {str(k): str(v) for k, v in errors.items() if v}


def manifest_line_for(manifest_text: str, dependency: str) -> int | None:
    """The first line of a manifest that names ``dependency``, or None.

    GuardDog's JSON for ``verify`` does not say where a dependency is declared.
    The first line containing the name as a whole token is close enough to land
    a finding on the right entry for every manifest format GuardDog reads.
    """
    if not dependency:
        return None
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_.\-/@]){re.escape(dependency)}(?![A-Za-z0-9_\-])",
        re.IGNORECASE,
    )
    for index, text in enumerate(manifest_text.splitlines(), start=1):
        if pattern.search(text):
            return index
    return None


@ash_scanner_plugin
class GuardDogScanner(ScannerPluginBase[GuardDogScannerConfig]):
    """Malicious-package heuristics (GuardDog) over the packages in the target."""

    #: Opt-in: a new builtin must not change the default scan of an existing
    #: user. Omitted from results until enabled (config ``enabled: true`` or
    #: named in ``--scanners``); see core/scanner_opt_in.py.
    OPT_IN: ClassVar[bool] = True

    #: Local ``scan`` is offline: the YARA rules ship inside the GuardDog
    #: package. ``verify`` needs the network and is refused under ASH_OFFLINE.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    @property
    def _opts(self) -> GuardDogScannerConfigOptions:
        """The options, typed. ``config`` is set in ``model_post_init``."""
        return cast(GuardDogScannerConfig, self.config).options

    @property
    def _ctx(self) -> PluginContext:
        """The plugin context, typed. ScannerPluginBase refuses to construct without one."""
        return cast(PluginContext, self.context)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = GuardDogScannerConfig()
        self.command = _COMMAND
        self.tool_type = ScannerToolType.SCA
        self.use_uv_tool = True
        self._setup_uv_tool_install_commands()
        self.tool_version = self._get_uv_tool_version("guarddog")
        self.description = (
            "GuardDog detects malicious-package heuristics in PyPI, npm, Go, "
            "GitHub Action, RubyGems and crates packages."
        )
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg=None,
            scan_path_arg=None,
            extra_args=[],
        )
        # Per-scan state. Reset at the top of scan(); see cfn_nag_scanner for why
        # counters must not carry over from a previous target.
        self.targets_attempted = 0
        self.targets_failed = 0
        self._sandbox_unavailable = False
        self._rule_args_for: Dict[str, List[str]] = {}
        self._skip_ecosystems: set[str] = set()
        self._rules_error: Dict[str, str] = {}
        super().model_post_init(context)

    # ------------------------------------------------------------------
    # Installation (uv tool, #708)
    # ------------------------------------------------------------------

    def _get_tool_version_constraint(self) -> str | None:
        if self._opts.tool_version:
            return self._opts.tool_version
        return GUARDDOG_DEFAULT_VERSION_CONSTRAINT

    def _get_tool_python_request(self) -> str | None:
        return GUARDDOG_PYTHON_REQUEST

    def unsupported_platform_reason(self) -> str | None:
        """Windows, at the pinned version: GuardDog cannot be installed there.

        GuardDog 3.2.0 depends on nono-py, which publishes wheels for Linux and
        macOS only, and whose source does not build on Windows (its Rust crate
        uses ``std::os::unix``). Measured on windows-latest in CI: ``uv tool
        install guarddog==3.2.0`` fails compiling nono. So on Windows an enabled
        GuardDog is SKIPPED with this reason rather than MISSING, the same
        treatment semgrep gets, and ``ash dependencies install`` does not try.
        """
        if platform.system().lower() == "windows":
            return (
                "GuardDog 3.2.0 cannot be installed on Windows: its dependency "
                "nono-py publishes no Windows build and does not compile there"
            )
        return None

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """No install command on Windows; see ``unsupported_platform_reason``."""
        if platform.lower() == "windows":
            return []
        return super().get_installation_commands(platform, arch)

    def validate_plugin_dependencies(self) -> bool:
        """Same resolution order as bandit and checkov: uv tool, pre-installed, install."""
        if self.dependency_unavailable_reason:
            return False
        if self.unsupported_platform_reason() is not None:
            return False
        if not self._validate_uv_tool_availability():
            if get_uv_tool_command(_COMMAND) is not None:
                self.use_uv_tool = False
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False

        if self.use_uv_tool:
            installation_info = self._get_tool_installation_info()
            if installation_info.get("available"):
                return self._select_tool_execution(installation_info)

            self._plugin_log(
                "GuardDog not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )
            timeout = self._opts.install_timeout
            if self._install_uv_tool(timeout=timeout):
                self._plugin_log(
                    "Successfully installed guarddog via UV tool", level=logging.INFO
                )
                self.dependencies_satisfied = True
                return True
            self._plugin_log(
                "UV tool installation failed for guarddog, falling back to consolidated resolver",
                level=logging.WARNING,
            )

        if get_uv_tool_command(_COMMAND) is not None:
            return True
        self._record_missing_reason()
        return False

    def _record_missing_reason(self) -> None:
        """Say why GuardDog is unavailable and how to provide it.

        The two cases that reach here without a uv error worth reading are
        offline mode, where ASH does not install anything, and ``--mode nix``,
        which is offline and whose flake does not carry GuardDog (it is not in
        nixpkgs). Both need the same remedy: install it before going offline.
        """
        requirement = f"guarddog{self._get_tool_version_constraint() or ''}"
        install = (
            f"uv tool install --python '{GUARDDOG_PYTHON_REQUEST}' '{requirement}'"
        )
        if self._is_offline_mode():
            reason = (
                "guarddog is not installed, and ASH does not install tools in "
                "offline mode. It is not in nixpkgs, so `ash scan --mode nix` does "
                f"not provide it either. Install it before going offline (`{install}`), "
                "use the ASH container image, which includes it, or leave the "
                "guarddog scanner disabled."
            )
        else:
            reason = (
                f"guarddog could not be installed or found on PATH. Install it with "
                f"`{install}`, or see the log above for uv's error."
            )
        self.dependency_unavailable_reason = reason
        self._plugin_log(reason, level=logging.ERROR)

    # ------------------------------------------------------------------
    # Target discovery and staging
    # ------------------------------------------------------------------

    def _candidate_files(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """Every file under ``target`` ASH would scan, as absolute paths.

        The source scan set, or every file under the converted directory, less
        KNOWN_IGNORE_PATHS components, ASH's output directory, the global ignore
        paths and ``options.excluded_paths``. Symlinks are dropped here, so
        nothing reachable only through one is ever staged.
        """
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        target = Path(target).absolute()
        if target_type == "converted":
            listed = [
                Path(root, name)
                for root, _dirs, files in os.walk(target)
                for name in files
            ]
        else:
            listed = [
                Path(item)
                for item in scan_set(
                    source=str(self._ctx.source_dir),
                    output=str(self._ctx.output_dir),
                )
            ]

        ignored_components = {p.strip("/") for p in KNOWN_IGNORE_PATHS}
        output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).absolute()
        patterns = [p.path for p in global_ignore_paths or []] + [
            p.path for p in self._opts.excluded_paths
        ]

        kept: List[Path] = []
        for item in listed:
            absolute = item if item.is_absolute() else source_dir / item
            absolute = Path(os.path.abspath(absolute))
            if not absolute.is_relative_to(target):
                continue
            if target_type == "source" and absolute.is_relative_to(output_dir):
                continue
            if absolute.is_symlink() or not absolute.is_file():
                continue
            rel_to_target = absolute.relative_to(target)
            if any(part in ignored_components for part in rel_to_target.parts[:-1]):
                continue
            if patterns:
                rel_to_source = (
                    absolute.relative_to(source_dir).as_posix()
                    if absolute.is_relative_to(source_dir)
                    else absolute.as_posix()
                )
                if any(
                    file_path_matches(rel_to_source, pattern) for pattern in patterns
                ):
                    continue
            kept.append(absolute)
        return sorted(set(kept))

    def _label(self, path: Path) -> str:
        source_dir = Path(self._ctx.source_dir).absolute()
        if path.is_relative_to(source_dir):
            rel = path.relative_to(source_dir).as_posix()
            return "" if rel == "." else rel
        return path.as_posix()

    def _discover_targets(
        self, target: Path, files: List[Path]
    ) -> Tuple[Dict[Tuple[str, Path], List[Path]], List[_Target]]:
        """Package roots per ecosystem with the files each one owns, plus verify targets."""
        target = Path(target).absolute()
        roots: Dict[str, set[Path]] = {eco: set() for eco in self._opts.ecosystems}
        verify_targets: List[_Target] = []
        for path in files:
            for ecosystem in self._opts.ecosystems:
                if _is_package_manifest(ecosystem, path.name):
                    roots[ecosystem].add(path.parent)
                if self._opts.verify and _is_verify_manifest(
                    ecosystem, path.relative_to(target).as_posix()
                ):
                    verify_targets.append(
                        _Target("verify", ecosystem, path, self._label(path))
                    )

        owned: Dict[Tuple[str, Path], List[Path]] = {}
        for eco_name, eco_roots in roots.items():
            ordered = sorted(eco_roots, key=lambda p: (len(p.parts), p.as_posix()))
            for root in ordered:
                nested = [
                    other
                    for other in ordered
                    if other != root and other.is_relative_to(root)
                ]
                owned[(eco_name, root)] = [
                    f
                    for f in files
                    if f.is_relative_to(root)
                    and not any(f.is_relative_to(n) for n in nested)
                ]
        verify_targets.sort(key=lambda t: (t.ecosystem, t.label))
        return owned, verify_targets

    @staticmethod
    def _stage(root: Path, files: List[Path], staging_dir: Path) -> None:
        """Hard-link (or copy) ``files`` under ``staging_dir``, keeping paths relative to ``root``."""
        for source in files:
            destination = staging_dir / source.relative_to(root)
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(source, destination)
            except OSError:
                shutil.copyfile(source, destination)

    # ------------------------------------------------------------------
    # Running GuardDog
    # ------------------------------------------------------------------

    def _rule_args(self, ecosystem: str) -> List[str]:
        """--rules/--exclude-rules for one ecosystem, from _prepare_rules."""
        return list(self._rule_args_for.get(ecosystem, []))

    def _list_rules(
        self, ecosystem: str, invocation_dir: Path
    ) -> Tuple[set[str], str | None]:
        """The rule names GuardDog accepts for one ecosystem; (names, failure reason)."""
        response, stdout, stderr = self._invoke(
            [_COMMAND, ecosystem, "list-rules"],
            invocation_dir,
            float(self._opts.install_timeout),
        )
        reason = self._failure(response, stdout, stderr, self._opts.install_timeout)
        if reason is not None:
            return set(), f"could not list its rules: {reason}"
        names: set[str] = set()
        for line in stdout.splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) >= 2 and _RULE_NAME.match(cells[1]):
                names.add(cells[1])
        if not names:
            return set(), "could not list its rules: list-rules printed no rule names"
        return names, None

    def _prepare_rules(self, ecosystems: Iterable[str], results_dir: Path) -> List[str]:
        """Resolve options.rules/exclude_rules per ecosystem; return config errors.

        GuardDog validates each name against the rules of the ecosystem being
        scanned, and the sets differ: a metadata rule such as ``typosquatting``
        exists for pypi and npm but not for github_action, which then exits 2 on
        ``--exclude-rules typosquatting``. So each ecosystem gets the configured
        names it knows. An exclusion it does not know is irrelevant to it; a
        rules selection none of whose names it knows leaves nothing to run, so
        that ecosystem is not scanned at all (running it without --rules would
        run every rule). A name no scanned ecosystem knows is a configuration
        error, reported as a failed run, since it is most likely a typo.

        Costs one list-rules call per ecosystem, and only when either option
        is set.
        """
        self._rule_args_for = {}
        self._skip_ecosystems = set()
        self._rules_error = {}
        configured = list(self._opts.rules) + list(self._opts.exclude_rules)
        if not configured:
            return []
        known_anywhere: set[str] = set()
        wanted = sorted(set(ecosystems))
        for ecosystem in wanted:
            names, reason = self._list_rules(
                ecosystem, results_dir / "invocations" / f"list-rules-{ecosystem}"
            )
            if reason is not None:
                self._rules_error[ecosystem] = reason
                continue
            known_anywhere |= names
            args: List[str] = []
            if self._opts.rules:
                selected = [r for r in self._opts.rules if r in names]
                if not selected:
                    self._skip_ecosystems.add(ecosystem)
                    continue
                if all(r in _METADATA_ONLY_HINT for r in selected):
                    self._plugin_log(
                        f"options.rules selects only metadata rules for {ecosystem} "
                        f"({', '.join(selected)}). GuardDog evaluates metadata rules "
                        "on a local scan only when given package metadata, so the "
                        "local scan checks nothing; they do run under options.verify.",
                        level=logging.WARNING,
                    )
                for rule in selected:
                    args.extend(["--rules", rule])
            for rule in self._opts.exclude_rules:
                if rule in names:
                    args.extend(["--exclude-rules", rule])
            self._rule_args_for[ecosystem] = args
        # Only judged when at least one ecosystem's rule list was read.
        if len(self._rules_error) == len(wanted):
            return []
        unknown = sorted(set(configured) - known_anywhere)
        if not unknown:
            return []
        message = (
            "options.rules/exclude_rules name(s) no scanned ecosystem has: "
            f"{', '.join(unknown)}. See `guarddog <ecosystem> list-rules`."
        )
        return [message]

    def _invoke(
        self,
        argv: List[str],
        invocation_dir: Path,
        timeout: float | None,
        env: Dict[str, str] | None = None,
    ) -> Tuple[Dict[str, Any], str, str]:
        """Run GuardDog once and return (response, stdout, stderr)."""
        if invocation_dir.exists():
            shutil.rmtree(invocation_dir)
        invocation_dir.mkdir(parents=True)
        response = self._run_subprocess(
            command=argv,
            results_dir=invocation_dir,
            stdout_preference="write",
            stderr_preference="write",
            cwd=invocation_dir,
            env=env,
            timeout=timeout,
        )

        def read(stream: str) -> str:
            log = invocation_dir / f"{self.__class__.__name__}.{stream}.log"
            try:
                return log.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""

        stderr = read("stderr")
        if not stderr and isinstance(response, dict) and response.get("error"):
            stderr = str(response.get("error"))
        return response, read("stdout"), stderr

    @staticmethod
    def _failure(
        response: Dict[str, Any], stdout: str, stderr: str, timeout: float | None
    ) -> str | None:
        """Why one invocation produced no usable result, or None if it did."""
        if response.get("timed_out"):
            return f"timed out after {timeout}s and was killed"
        if response.get("error") and "returncode" not in response:
            return f"could not be run: {response.get('error')}"
        returncode = response.get("returncode", 1)
        if returncode != 0:
            excerpt = stderr.strip().splitlines()[-1] if stderr.strip() else "no stderr"
            return f"exited {returncode}: {excerpt}"
        if not stdout.strip():
            return "exited 0 but printed no result"
        return None

    def _scan_package(
        self, target: _Target, staging: Path, invocation_dir: Path
    ) -> Tuple[Dict[str, Any] | None, str | None]:
        """Run ``scan`` on one staged package root; (document, failure reason)."""
        base = [
            _COMMAND,
            target.ecosystem,
            "scan",
            staging.as_posix(),
            "--output-format",
            "json",
        ]
        mode = self._opts.sandbox
        timeout = self._effective_scan_timeout()
        if mode == "disabled" or (mode == "auto" and self._sandbox_unavailable):
            argv = base + ["--no-sandbox"] + self._rule_args(target.ecosystem)
        elif mode == "required":
            argv = base + ["--sandbox"] + self._rule_args(target.ecosystem)
        else:
            argv = base + self._rule_args(target.ecosystem)

        response, stdout, stderr = self._invoke(argv, invocation_dir, timeout)
        if (
            mode == "auto"
            and not self._sandbox_unavailable
            and response.get("returncode") not in (0, None)
            and _SANDBOX_UNAVAILABLE_MARKER in stderr
        ):
            self._sandbox_unavailable = True
            self._plugin_log(
                "GuardDog's kernel sandbox is not available on this platform; "
                "scanning without it (options.sandbox: auto). Set "
                "scanners.guarddog.options.sandbox to 'required' to treat this "
                "as an error instead.",
                level=logging.WARNING,
            )
            argv = base + ["--no-sandbox"] + self._rule_args(target.ecosystem)
            response, stdout, stderr = self._invoke(argv, invocation_dir, timeout)

        reason = self._failure(response, stdout, stderr, timeout)
        if reason is not None:
            if _SANDBOX_UNAVAILABLE_MARKER in stderr:
                reason = (
                    "GuardDog's kernel sandbox is not available on this platform and "
                    "options.sandbox is 'required'"
                )
            return None, reason
        try:
            document = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return None, f"printed output that is not JSON ({exc})"
        if not isinstance(document, dict):
            return None, "printed JSON that is not a scan result object"
        errors = guarddog_errors(document)
        if errors:
            joined = "; ".join(f"{k}: {v}" for k, v in sorted(errors.items()))
            return document, f"reported errors, so some rules did not run: {joined}"
        return document, None

    def _verify_manifest(
        self, target: _Target, invocation_dir: Path
    ) -> Tuple[List[Dict[str, Any]] | None, str | None]:
        """Run ``verify`` on one manifest; (entries, failure reason)."""
        argv = [
            _COMMAND,
            target.ecosystem,
            "verify",
            target.path.as_posix(),
            "--output-format",
            "json",
        ] + self._rule_args(target.ecosystem)
        env = {
            **os.environ,
            "GUARDDOG_PARALLELISM": str(self._opts.verify_parallelism),
        }
        timeout = float(self._opts.verify_timeout)
        response, stdout, stderr = self._invoke(argv, invocation_dir, timeout, env=env)
        reason = self._failure(response, stdout, stderr, timeout)
        if reason is not None:
            return None, reason
        try:
            entries = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return None, f"printed output that is not JSON ({exc})"
        if not isinstance(entries, list):
            return None, "printed JSON that is not a list of dependency results"
        problems = [
            line.strip()
            for line in stderr.splitlines()
            if _GUARDDOG_ERROR_LINE.match(line.strip())
        ]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            result: Dict[str, Any] = (
                entry["result"] if isinstance(entry.get("result"), dict) else {}
            )
            for key, value in guarddog_errors(result).items():
                problems.append(f"{entry.get('dependency')}: {key}: {value}")
        if problems:
            # Kept as a failure even with entries present: a dependency GuardDog
            # could not fetch or analyze is one it did not check.
            return entries, "; ".join(problems[:10]) + (
                f" (and {len(problems) - 10} more)" if len(problems) > 10 else ""
            )
        return entries, None

    # ------------------------------------------------------------------
    # scan()
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Dict[Any, Any] | None]:
        """Abstract stub: GuardDog overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: GuardDogScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        if global_ignore_paths is None:
            global_ignore_paths = []
        self.targets_attempted = 0
        self.targets_failed = 0
        self._sandbox_unavailable = False

        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        try:
            return self._scan_target(Path(target), target_type, global_ignore_paths)
        except ScannerError:
            raise
        except Exception as exc:
            raise ScannerError(f"{self.__class__.__name__} failed: {exc}") from exc

    def _scan_target(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> SarifReport:
        results_dir = Path(cast(Path, self.results_dir)).joinpath(target_type)
        results_dir.mkdir(parents=True, exist_ok=True)
        files = self._candidate_files(target, target_type, global_ignore_paths)
        owned, verify_targets = self._discover_targets(target, files)

        rules: Dict[str, ReportingDescriptor] = {}
        results: List[Result] = []
        failures: List[str] = []
        seen: Dict[Tuple[Any, ...], int] = {}
        kept_severity: List[str] = []
        severity_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

        def add(converted: _Converted) -> None:
            for rule_id, descriptor in converted.rules.items():
                rules.setdefault(rule_id, descriptor)
            for result, key, severity in zip(
                converted.results, converted.keys, converted.severities
            ):
                # One finding per rule and place: a file under two package roots
                # of different ecosystems (a .js file in a Python package that
                # also has a package.json below it) is matched by both scans.
                if key in seen:
                    index = seen[key]
                    if severity_rank[severity] > severity_rank[kept_severity[index]]:
                        results[index] = result
                        kept_severity[index] = severity
                    continue
                seen[key] = len(results)
                results.append(result)
                kept_severity.append(severity)

        if not owned and not verify_targets:
            self._plugin_log(
                f"No {', '.join(self._opts.ecosystems)} packages or "
                f"manifests found in {target_type} directory; nothing for GuardDog to scan.",
                target_type=target_type,
                level=logging.INFO,
            )

        failures.extend(
            self._prepare_rules(
                {eco for eco, _ in owned} | {t.ecosystem for t in verify_targets},
                results_dir,
            )
        )

        def not_run(ecosystem: str, what: str) -> bool:
            """True when a target of this ecosystem must not be run, recording why."""
            if ecosystem in self._rules_error:
                self.targets_attempted += 1
                self.targets_failed += 1
                failures.append(f"{ecosystem} {what}: {self._rules_error[ecosystem]}")
                return True
            if ecosystem in self._skip_ecosystems:
                self._plugin_log(
                    f"Not running GuardDog on {ecosystem} {what}: none of options.rules "
                    "exists for that ecosystem.",
                    target_type=target_type,
                    level=logging.INFO,
                )
                return True
            return False

        staging_parent = Path(tempfile.mkdtemp(prefix="ash-guarddog-"))
        try:
            for index, ((ecosystem, root), root_files) in enumerate(
                sorted(owned.items(), key=lambda kv: (kv[0][0], kv[0][1].as_posix()))
            ):
                label = self._label(root)
                if not_run(ecosystem, f"scan of {label or '.'}"):
                    continue
                self.targets_attempted += 1
                staging = staging_parent / f"{index:04d}"
                staging.mkdir()
                self._stage(root, root_files, staging)
                document, reason = self._scan_package(
                    _Target("scan", ecosystem, root, label),
                    staging,
                    results_dir / "invocations" / f"scan-{index:04d}",
                )
                if document is not None:
                    add(
                        convert_guarddog_scan_result(
                            document,
                            uri_prefix=label,
                            ecosystem=ecosystem,
                            include_capabilities=self._opts.include_capabilities,
                        )
                    )
                if reason is not None:
                    self.targets_failed += 1
                    failures.append(f"{ecosystem} scan of {label or '.'}: {reason}")
        finally:
            shutil.rmtree(staging_parent, ignore_errors=True)

        offline = self._is_offline_mode()
        for index, vtarget in enumerate(verify_targets):
            if not_run(vtarget.ecosystem, f"verify of {vtarget.label}"):
                continue
            self.targets_attempted += 1
            if offline:
                self.targets_failed += 1
                failures.append(
                    f"{vtarget.ecosystem} verify of {vtarget.label}: not attempted, "
                    "because options.verify downloads every dependency from its "
                    "registry and ASH is in offline mode (ASH_OFFLINE). Set "
                    "scanners.guarddog.options.verify to false for offline scans."
                )
                continue
            entries, reason = self._verify_manifest(
                vtarget, results_dir / "invocations" / f"verify-{index:04d}"
            )
            if entries is not None:
                try:
                    manifest_text = vtarget.path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    manifest_text = ""
                for entry in entries:
                    if not isinstance(entry, dict) or not isinstance(
                        entry.get("result"), dict
                    ):
                        continue
                    name = str(entry.get("dependency") or "")
                    version = entry.get("version")
                    add(
                        convert_guarddog_scan_result(
                            entry["result"],
                            uri_prefix="",
                            ecosystem=vtarget.ecosystem,
                            include_capabilities=self._opts.include_capabilities,
                            dependency=(name, str(version) if version else None),
                            manifest_uri=vtarget.label,
                            manifest_line=manifest_line_for(manifest_text, name),
                        )
                    )
            if reason is not None:
                self.targets_failed += 1
                failures.append(
                    f"{vtarget.ecosystem} verify of {vtarget.label}: {reason}"
                )

        self._post_scan(target=target, target_type=target_type)
        for failure in failures:
            self.errors.append(failure)
            self._plugin_log(failure, target_type=target_type, level=logging.ERROR)

        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent.model_validate(
                            {
                                "name": "GuardDog",
                                "version": self.tool_version,
                                "informationUri": "https://github.com/DataDog/guarddog",
                                "rules": [rules[k] for k in sorted(rules)],
                            }
                        )
                    ),
                    results=results,
                    invocations=[
                        Invocation(
                            commandLine=f"guarddog <ecosystem> scan|verify ({self.targets_attempted} invocation(s))",
                            startTimeUtc=self.start_time,
                            endTimeUtc=self.end_time,
                            executionSuccessful=not failures,
                            exitCode=self.exit_code,
                            exitCodeDescription="\n".join(failures),
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        results_dir.joinpath("guarddog.sarif").write_text(
            report.model_dump_json(exclude_none=True, exclude_unset=True),
            encoding="utf-8",
        )

        if failures:
            # Every invocation that failed is a package or manifest GuardDog did not
            # check, so the run is not a clean scan however many others succeeded --
            # the same reasoning as cfn_nag_scanner's unrendered templates. Raised
            # after the report is on disk so the findings that were produced are kept.
            if self.targets_failed:
                summary = (
                    f"GuardDog did not complete {self.targets_failed} of "
                    f"{self.targets_attempted} target(s), so this run is not a clean scan"
                )
            else:
                summary = "GuardDog's configuration is not usable, so this run is not a clean scan"
            raise ScannerError(f"{summary}: {' | '.join(failures)}")
        return report
