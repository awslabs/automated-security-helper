# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""YARA-X: a file pattern engine run with the operator's own rules, as an alpha plugin.

What it runs
------------
``yr scan`` (the YARA-X command line, executable ``yr``) over the scan target, with a
rule set the operator supplies. YARA-X is VirusTotal's Rust rewrite of YARA. It ships
no rules of its own, so this scanner is bring-your-own-rules: with no
``options.rules_path`` configured it does nothing and says so at INFO (see "The rules
gate"). Listing the module in ``ash_plugin_modules`` is the opt-in, as for every
alpha plugin; a scan that does not list it is unchanged.

The scanner's name is ``yara-x`` (a scanner name is lower-case and hyphen-separated),
so its configuration section is ``scanners.yara-x``; the package keeps the Python
spelling, ``ash_yara_x_plugins``.

Why this scanner overrides ``scan()``
-------------------------------------
``yr scan`` has no option that writes a report to a file: its only report goes to
standard output. The template ``scan()`` reads a results file and expects SARIF, so
this plugin takes the second observed shape (hadolint and guarddog do the same): it
runs the tool with ``stdout_preference="return"``, converts the tool's own
newline-delimited JSON to SARIF itself, and does by hand what the template does
(reset the counters, skip an empty target, accept only ``success_exit_codes``).

Invocation
----------
Verified against the ``yr 1.23.0`` release binary (``yr --version`` prints
``yara-x-cli 1.23.0``) and the ``cli/src/commands/scan.rs`` and ``main.rs`` sources
at the same project. Every run carries these flags and none is configurable.

* ``--output-format=ndjson``: one JSON object per file that matched at least one rule,
  ``{"path": ..., "rules": [{"identifier": ..., "meta": [[key, value], ...],
  "tags": [...]}, ...]}``. A file that matched nothing prints nothing, so a clean scan
  has an empty standard output. ``meta`` is a list of ``[key, value]`` pairs, not an
  object (measured on the release binary).
* ``--print-meta``, ``--print-tags``: without them ``meta`` and ``tags`` are absent
  and the rule's own severity cannot be read.
* ``--disable-console-logs``: a rule that calls the ``console`` module would otherwise
  write its text to standard output, in the middle of the JSON.
* ``--recursive``: scan the directory's subdirectories. Written without a value
  (the flag takes an optional value only through ``=``) and added only when the target
  is a directory, because ``yr scan`` refuses it for a file target.
* ``--`` ends option parsing, and the rules path and the scan path follow it as two
  positional arguments. ``--print-strings`` is never passed: it puts the matched bytes
  in the output, and ASH reports where a rule matched, not what it matched.

The working directory is the source directory, so the scan path is ``.`` and a
reported path is source-relative (``./src/x`` is reported as ``src/x``). The converted
target is passed by absolute path.

Flags and options ASH never passes, so the scanned tree has nothing to reach:
``--scan-list`` (reads a list of paths from a file), ``--module-data`` (reads a file
into a module), ``--compiled-rules`` and ``--include-dir``. ``yr`` reads no
configuration file from the scanned tree and makes no network call.

``yr scan --recursive`` follows no symbolic link: a link to a file is not read and a link
to a directory is not descended, whether its target is inside the scanned tree or
outside it (measured on the release binary). So the command names no link, and nothing
a link leaving the tree points to is read.

Install
-------
``yr`` is installed from the pinned v1.23.0 release by the plugin's own installer
(``yara_x_install.py``: one release asset per platform, a SHA256 for each archive and
for the executable inside it), or found on ``PATH``.

The rules gate
--------------
The rules are the one input that decides what is found, so ``options.rules_path`` is
operator-only, the same as a ``config_file`` option elsewhere: used only when the
operator set it (a config outside every git checkout and the scanned directory, or
``--config-overrides``). From a config inside the tree it is ignored with a warning,
and the scan is then the no-rules no-op below. Unlike an option that hides findings,
the operator may keep the rules inside the scanned tree: the rules are theirs.

With no usable rules path the scanner does not run the tool. It logs at INFO that no
rule set is configured and the scan reports "nothing scanned" (``targets_attempted``
stays 0, ``nothing_scanned_reason`` says why), not a pass. This is how a bring-your-own
scanner is gated; snyk-code gates on credentials in the same spirit (it warns and is
only loaded by an operator). A path that is set by the operator and does not exist
fails the scan: running with no rules would report a scan that checked nothing.

A rule path is passed to ``yr`` in its ``[NAMESPACE:]RULES_PATH`` positional form, so a
path that contains a colon (other than a Windows drive letter) would be read as a
namespace and is refused.

Severity
--------
YARA has no severity of its own. The scanner reads the rule's own ``severity`` metadata
(``meta: severity = "high"``), case-insensitively:

* ``critical`` -> CRITICAL, ``high`` -> HIGH (both SARIF ``error``)
* ``medium`` -> MEDIUM (``warning``)
* ``low`` -> LOW (``note``)
* ``info`` -> INFO (``none``)
* no ``severity`` metadata -> INFO (``none``), as the rule did not say it matters
* a ``severity`` value that is not one of the above -> MEDIUM (``warning``): the rule
  author meant something, and the scanner errs toward reporting it rather than
  rating it as informational.

``issue_severity`` and the SARIF level are set together from one table
(``YARA_SEVERITY_MAP``), so level-reading consumers agree with ASH's severity.

Exit status and output
----------------------
``yr scan`` exits 0 whether or not a rule matched, and 1 for an error it cannot go on
after (a rules path that does not open, a rule that does not compile). So 0 is the only
success code, and any other code fails the scan. A file ``yr`` could not read is
printed to its standard error and the scan continues with exit 0; ASH does not see
that, which is a named limit. The tool's output is JSON on standard output, and a line
that is not a JSON object with a ``path`` and a ``rules`` list fails the scan rather
than reading as a clean one.

Offline
-------
Rules are read from disk and ``yr scan`` makes no network call.

Sandbox
-------
The strict default: no network, and no variables or paths beyond the baseline. An
operator rules path outside the scanned tree is not mounted into a sandbox yet; grants
derived from options wait for the sandbox's grant gates.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
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
from automated_security_helper.plugin_modules.ash_yara_x_plugins.yara_x_install import (
    YARA_X_VERSION,
    yara_x_install_commands,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Level,
    SarifReport,
)
from automated_security_helper.utils.config_trust import (
    LEADS_OUT_OF_THE_TREE,
    operator_path,
    refusal_warning,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The YARA-X command line executable.
YARA_X_COMMAND = "yr"

#: ``severity`` metadata value (lower case) -> (ASH severity, SARIF level). See the
#: module docstring.
YARA_SEVERITY_MAP: Dict[str, Tuple[str, Level]] = {
    "critical": ("CRITICAL", Level.error),
    "high": ("HIGH", Level.error),
    "medium": ("MEDIUM", Level.warning),
    "low": ("LOW", Level.note),
    "info": ("INFO", Level.none),
}

#: A rule with no ``severity`` metadata.
NO_SEVERITY: Tuple[str, Level] = ("INFO", Level.none)

#: A rule whose ``severity`` metadata is not one of ``YARA_SEVERITY_MAP``'s keys.
UNRECOGNIZED_SEVERITY: Tuple[str, Level] = ("MEDIUM", Level.warning)

#: ``yr scan`` reads ``NAMESPACE:PATH``; a Windows drive letter is the one colon a
#: path may carry.
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:[\\/]")


class YaraXScannerConfigOptions(ScannerOptionsBase):
    rules_path: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to the YARA rules to scan with: one .yar or .yara file, or a "
                "directory searched recursively for them. YARA-X ships no rules, so "
                "with this unset the scanner does nothing and says so at INFO. A "
                "relative path is taken from the directory of the config file that "
                "sets it, or from the working directory for --config-overrides, not "
                f"from the source directory. {SET_BY_THE_OPERATOR} A path that is set "
                "and does not exist fails the scan; a path containing a colon is "
                "refused."
            ),
        ),
    ] = None


class YaraXScannerConfig(ScannerPluginConfigBase):
    name: Literal["yara-x"] = "yara-x"
    enabled: bool = True
    options: Annotated[
        YaraXScannerConfigOptions,
        Field(description="Configure the yara-x scanner"),
    ] = YaraXScannerConfigOptions()


def _first_value(meta: Any) -> Dict[str, Any]:
    """A rule's ``meta`` as a dict, taking the first value of a repeated key.

    ``yr`` prints ``meta`` as a list of ``[key, value]`` pairs; a dict is accepted too.
    """
    if isinstance(meta, dict):
        return dict(meta)
    out: Dict[str, Any] = {}
    if isinstance(meta, list):
        for pair in meta:
            if (
                isinstance(pair, (list, tuple))
                and len(pair) == 2
                and isinstance(pair[0], str)
            ):
                out.setdefault(pair[0], pair[1])
    return out


def severity_for(meta: Dict[str, Any]) -> Tuple[str, Level]:
    """(ASH severity, SARIF level) for a rule's metadata."""
    if "severity" not in meta:
        return NO_SEVERITY
    value = meta["severity"]
    if isinstance(value, str) and value.strip().lower() in YARA_SEVERITY_MAP:
        return YARA_SEVERITY_MAP[value.strip().lower()]
    return UNRECOGNIZED_SEVERITY


def parse_ndjson(stdout: str) -> List[Dict[str, Any]]:
    """The per-file objects in ``yr scan --output-format=ndjson`` output.

    Raises:
        ScannerError: a non-blank line is not a JSON object with a ``path`` string and
            a ``rules`` list. The line is not quoted: it can hold the scanned tree's
            text.
    """
    objects: List[Dict[str, Any]] = []
    for number, line in enumerate(stdout.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            document = json.loads(line)
        except ValueError:
            raise ScannerError(
                f"yr wrote output that is not JSON on line {number}, so its "
                "findings could not be graded"
            ) from None
        if (
            not isinstance(document, dict)
            or not isinstance(document.get("path"), str)
            or not isinstance(document.get("rules"), list)
        ):
            raise ScannerError(
                f"yr wrote a JSON value on line {number} that is not a file result "
                "with a path and a rules list, so its findings could not be graded"
            )
        objects.append(document)
    return objects


def _uri(path: str, source_dir: Path) -> str:
    """The reported path as a source-relative posix URI."""
    text = path.replace("\\", "/")
    candidate = Path(text)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(source_dir.absolute()).as_posix()
        except ValueError:
            return text
    while text.startswith("./"):
        text = text[2:]
    return text


def convert_ndjson(
    objects: List[Dict[str, Any]], *, source_dir: Path, tool_version: str | None
) -> Dict[str, Any]:
    """A SARIF document (as a dict) for the per-file objects ``yr`` printed."""
    results: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}
    for document in objects:
        uri = _uri(document["path"], source_dir)
        for rule in document["rules"]:
            if not isinstance(rule, dict) or not isinstance(
                rule.get("identifier"), str
            ):
                continue
            rule_id = rule["identifier"]
            meta = _first_value(rule.get("meta"))
            severity, level = severity_for(meta)
            description = meta.get("description")
            text = (
                description
                if isinstance(description, str) and description.strip()
                else f"YARA rule {rule_id} matched"
            )
            tags = [t for t in (rule.get("tags") or []) if isinstance(t, str)]
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": text},
                    "properties": {"tags": ["yara-x", *tags]},
                },
            )
            fingerprint = hashlib.sha256(f"{rule_id}\0{uri}".encode()).hexdigest()
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level.value,
                    "message": {"text": text},
                    "locations": [
                        {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                    ],
                    "partialFingerprints": {"yara_x/v1": fingerprint[:32]},
                    "properties": {
                        "issue_severity": severity,
                        "tags": tags,
                        "yara_tags": tags,
                    },
                }
            )
    driver: Dict[str, Any] = {
        "name": "yara-x",
        "informationUri": "https://virustotal.github.io/yara-x/",
        "rules": list(rules.values()),
    }
    if tool_version:
        driver["version"] = tool_version
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


@ash_scanner_plugin
class YaraXScanner(ScannerPluginBase[YaraXScannerConfig]):
    """File pattern matching over the scan target using YARA-X and operator rules."""

    #: Not Python-only: ``yr`` is a native binary installed from its pinned release.
    python_only: ClassVar[bool | None] = False

    # Rules are read from disk and ``yr scan`` makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. The native fields name ``yr``'s own ndjson (the capture in
    #: tests/test_data/scanners/yara_x/captured), which this adapter converts to SARIF.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rules[]."identifier"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rules[]."meta" pair "severity" (operator-written rule '
            "metadata, not a field YARA-X defines), through YARA_SEVERITY_MAP",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='"path" (the matched file)',
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="a YARA match is a file-level result here: ASH never passes "
            "--print-strings, so the output carries no match offsets, and the "
            "result has a file location and no region",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="a file-level result; ASH never passes --print-strings, so "
            "the output carries no match offsets",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rules[]."meta" pair "description" (falls back to '
            "'YARA rule <id> matched')",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="a finding names a matched file, not a deployable resource",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="a finding names a matched file, not a deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="a pattern match over files carries no package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="a pattern match over files carries no package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="a pattern match over files carries no package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="YARA-X ships no rules and its output has no CVE field; a rule "
            "author's own meta pair is not read as one",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="YARA-X ships no rules and its output has no CWE field; a rule "
            "author's own meta pair is not read as one",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["yara_x/v1"], a sha256 the adapter '
            "computes over the rule identifier and the path (not a native field)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="a pattern match carries no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the output has no remediation field; a rule author's own "
            "meta pair is not read as one",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="ASH never passes --print-strings: it reports where a rule "
            "matched, not the matched bytes, so no snippet exists",
        ),
        references=FacetDecl(
            state=FacetState.DROPPED,
            native_field='rules[]."meta" pairs other than severity and '
            "description (a rule author's own reference key, if any)",
            reason="the adapter reads the meta list into one dict and carries "
            "only severity and description; any other pair is discarded",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='rules[]."tags", written as the SARIF rule property '
            'tags (after "yara-x") and the result properties "tags" and '
            '"yara_tags"',
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "issue_severity" and "yara_tags", '
            "written by the adapter",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="yara-x",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "yara_x_scanner.py offline_strategy, sandbox_requirements; "
                    "module header (Offline): the rules are read from disk and "
                    "`yr scan` makes no network call"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="yr's own newline-delimited JSON on standard output, converted "
                "to SARIF by convert_ndjson",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SOURCE_CODE,),
                tool_type=ScannerToolType.SAST,
                selection=(
                    "`yr scan --recursive` over the target directory with the "
                    "operator's rules (module header: Invocation)"
                ),
                covers_note="an alpha scanner; it declares no covers display string",
                tool_type_note=(
                    "a YARA rule matches the bytes of any file, which fits no single "
                    "target kind; SAST is the closest of the types the register "
                    "serves (CUSTOM serves none), and the findings are file-level "
                    "pattern matches"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for YARA-X.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(yara_x_install.py: linux and darwin amd64/arm64, and windows/amd64; "
                "the release publishes no windows/arm64 build), not by the shared "
                "tool_downloads table, so the register lists none",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the rule's own severity metadata, mapped by YARA_SEVERITY_MAP; "
                "no metadata is INFO and an unrecognized value is MEDIUM",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason=(
                    "yr reads no ignore file and no inline comment from the scanned "
                    "tree (module header: yr reads no configuration file from the "
                    "scanned tree); the rules decide what matches, and ASH "
                    "suppressions are the surface this register records"
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under yara_x/v1 over rule and path",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.OPERATOR_PATHS,
                env_prefixes=(),
                options_surface=(
                    "options.rules_path, an operator-set path (a config outside the "
                    "scanned tree or --config-overrides); from a repository config it "
                    "is ignored with a warning"
                ),
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="yr scan exits 0 whether or not a rule matched and 1 on "
                "an error it cannot go on after, so 0 is the only success",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_yara_x_plugins in ash_plugin_modules",
                    "options.rules_path (no rules, no scan)",
                ),
                upstream_license="BSD-3-Clause (source: the LICENSE file in the "
                "repository at the v1.23.0 tag commit afe4585b, read 2026-11-26; the "
                "release archives carry no license file; no license or service "
                "gate, the binary is downloaded and never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no manifest or lockfile is required; the operator's rule set "
                "is the input, and with none the scanner reports nothing scanned",
            ),
        )
    )

    # ``yr scan`` exits 0 with or without matches and 1 on an error.
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = YaraXScannerConfig()
        self.command = YARA_X_COMMAND
        self.subcommands = ["scan"]
        # SAST, not CUSTOM: the register serves no target kind for CUSTOM (see the
        # tool_type_note in operational_facets).
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _argv; ToolArgs stays empty so nothing from the
        # base resolver can add a token yr would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "YaraXScanner":
        """Install from the pinned release asset in ``yara_x_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no YARA-X download
        table (it would name the executable ``yara-x``; the release's is ``yr``).
        This table never raises.
        """
        self.custom_install_commands.update(yara_x_install_commands())
        return self

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: yara-x overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("YaraXScanner has no plugin context")
        return self.context

    @property
    def _options(self) -> YaraXScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, YaraXScannerConfigOptions):
            return options
        return YaraXScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before ``yr`` runs which files a rule matches."""
        return None

    def _rules_path(self) -> Optional[Path]:
        """The operator's ``options.rules_path``, or None when there is none to use.

        Raises:
            ScannerError: the operator's path does not exist, leads out of the tree
                through a link, or holds a colon ``yr`` would read as a namespace.
        """
        value = self._options.rules_path
        if value is None or not str(value).strip():
            return None
        chosen = operator_path(
            self._ctx.config,
            "scanners.yara-x.options.rules_path",
            value,
            Path(self._ctx.source_dir),
            outside_tree=False,
        )
        if chosen.refusal == LEADS_OUT_OF_THE_TREE:
            raise ScannerError(
                f"scanners.yara-x.options.rules_path is {str(value)!r}, a path inside "
                "the scanned tree that resolves outside it through a symbolic link. "
                "The scanned repository decides what is at that path, so yr is not "
                "given it, and yr is not run."
            )
        if chosen.path is None:
            self._plugin_log(
                refusal_warning(
                    f"Ignoring scanners.yara-x.options.rules_path ({str(value)!r}): "
                    f"{chosen.refusal}.",
                    chosen.refusal,
                ),
                level=logging.WARNING,
            )
            return None
        text = chosen.path.as_posix()
        if ":" in text and not _DRIVE_PREFIX.match(text):
            raise ScannerError(
                "scanners.yara-x.options.rules_path contains a colon, which yr reads "
                "as a NAMESPACE:PATH separator. Move the rules to a path without one."
            )
        if not chosen.path.exists():
            raise ScannerError(
                f"scanners.yara-x.options.rules_path is {str(value)!r}, which does "
                f"not exist (looked for {text}). Fix the path or unset the option; "
                "yr is not run without rules."
            )
        return chosen.path

    def _argv(self, rules: Path, target: Path) -> List[str]:
        """``yr scan <flags> -- <rules> <target>``; see the module docstring."""
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = target.absolute()
        scan_path = "." if absolute == source_dir else absolute.as_posix()
        argv = [
            self.command or YARA_X_COMMAND,
            "scan",
            "--output-format=ndjson",
            "--print-meta",
            "--print-tags",
            "--disable-console-logs",
        ]
        if target.is_dir():
            argv.append("--recursive")
        argv.extend(["--", rules.as_posix(), scan_path])
        return argv

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: YaraXScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Run ``yr scan`` with the operator's rules and convert its output."""
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Per target, above every early return.
        self.targets_attempted = 0
        self.targets_failed = 0
        self.exit_code = 0
        self.start_time = None
        self.end_time = None
        self.output = []
        self._reset_errors()
        self._nothing_scanned_reason = None

        if self._target_is_empty(target):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=self.empty_target_log_level,
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

        self.exit_code = None
        final_args: List[str] = []
        try:
            rules = self._rules_path()
            if rules is None:
                reason = (
                    "yara-x has no rule set: scanners.yara-x.options.rules_path is "
                    "not set by the operator, and YARA-X ships no rules"
                )
                self._nothing_scanned_reason = reason
                self._plugin_log(
                    f"{reason}. Not running yr on {target_type}.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return True

            final_args = self._argv(rules, target)
            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            timeout = self._effective_scan_timeout()
            self.targets_attempted = 1
            response = self._run_subprocess(
                command=final_args,
                results_dir=results_dir,
                stdout_preference="return",
                stderr_preference="write",
                timeout=timeout,
            )
            self._post_scan(target=target, target_type=target_type)
            self._refuse_flagged_response(response, timeout)
            self._record_target_exit_code(response)
            self._refuse_rejected_exit_code()

            stdout = response.get("stdout") if isinstance(response, dict) else ""
            objects = parse_ndjson(stdout or "")
            document = convert_ndjson(
                objects,
                source_dir=Path(self._ctx.source_dir),
                tool_version=getattr(self, "tool_version", None),
            )
            report = SarifReport.model_validate(document)
            self._drop_excluded(report, target, global_ignore_paths)
            self._inject_invocation(report, final_args, target)
            return report
        except Exception as e:
            if self.end_time is None:
                from datetime import datetime, timezone

                self.end_time = datetime.now(timezone.utc)
            raise ScannerError(self._describe_scan_failure(e, None)) from e

    def _drop_excluded(
        self,
        report: SarifReport,
        target: Path,
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> None:
        """Remove results under ASH's own output directories or an ignore path.

        ``yr`` walks the whole target, ASH's earlier reports included, and has no
        option that skips a path.
        """
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        output_dirs = [
            d.as_posix().strip("/") for d in self._ash_output_dirs_inside(target)
        ]

        def excluded(uri: str) -> bool:
            for directory in output_dirs:
                if directory and (uri == directory or uri.startswith(directory + "/")):
                    return True
            return any(file_path_matches(uri, ip.path) for ip in global_ignore_paths)

        for run in report.runs:
            kept = []
            for result in run.results or []:
                locations = result.locations or []
                physical = locations[0].physicalLocation if locations else None
                # physicalLocation is a RootModel union: read through ``.root``.
                physical = getattr(physical, "root", physical)
                location = physical.artifactLocation if physical else None
                uri = location.uri if location is not None and location.uri else ""
                if uri and excluded(uri):
                    continue
                kept.append(result)
            run.results = kept

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or YARA_X_COMMAND)
        if not found:
            ASH_LOGGER.warning(
                f"yr (YARA-X {YARA_X_VERSION}) executable not found in PATH. Install "
                "it with `ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_yara_x_plugins\"]' --tool yara-x`."
            )
        return found is not None


__all__ = [
    "NO_SEVERITY",
    "UNRECOGNIZED_SEVERITY",
    "YARA_SEVERITY_MAP",
    "YARA_X_COMMAND",
    "YaraXScanner",
    "YaraXScannerConfig",
    "YaraXScannerConfigOptions",
    "convert_ndjson",
    "parse_ndjson",
    "severity_for",
]
