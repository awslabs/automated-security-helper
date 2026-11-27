# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Betterleaks: a secret scanner by gitleaks' author, as an alpha scanner plugin.

What it runs
------------
``betterleaks dir`` over the scan target: the files as they are on disk, not git
history, which is what ASH's builtin ``gitleaks`` scanner and detect-secrets read as
well. Betterleaks is the successor project to gitleaks (the gitleaks README says its
author is shifting focus to it), takes the same flags for everything this plugin
uses, and runs the same kind of rules (regular expressions with keyword prefilters)
plus entropy, token-efficiency and expression filters.

Betterleaks is an alpha plugin: it is loaded only when
``ash_betterleaks_plugins`` is listed in ``ash_plugin_modules`` (or passed with
``--ash-plugin-modules``), so a scan that does not list the module is unchanged by its
existence. It runs beside the builtin gitleaks scanner, not instead of it, so a secret
both find is reported twice, as a secret detect-secrets and gitleaks both find is.

The version is pinned at the 1.x maintenance line (``utils/tool_downloads.py``), not
the 2.0 release candidates.

Invocation
----------
Every run carries these flags, and none of them is configurable. Each was measured on
1.10.1, and the ones that differ from gitleaks are marked.

* ``--redact=100``: Betterleaks writes ``REDACTED`` in place of the secret, in its SARIF
  snippet and in its log. Written with ``=`` because the flag takes an optional value
  (``NoOptDefVal`` "100"): ``--redact 100`` would make ``100`` the scan path.
  ``_post_process_sarif`` also overwrites any snippet that is not ``REDACTED``.
* ``--exit-code=2``: Betterleaks exits 1 both when it finds leaks (its default
  ``--exit-code``) and when it fails (a fatal log line, a partial scan with errors).
  Moving the leaks code to 2 tells them apart, so 0 and 2 are success and 1 is a
  failure. An unknown flag exits 126.
* ``--no-banner``, ``--no-color``: the log goes to a file nobody reads in a terminal.
* ``--ignore-gitleaks-allow``: drops nothing; it makes Betterleaks stop honoring inline
  ``betterleaks:allow`` and ``gitleaks:allow`` comments (both, measured). See "Inline
  allow comments".
* ``--gitleaks-ignore-path=<empty directory ASH makes>``: see "Ignore files".

Report: ``--report-format=sarif --report-path=<file>``. Findings are SARIF results with
no ``level``; the driver is named ``betterleaks`` and its ``semanticVersion`` is
``v8.0.0`` whatever the release (a constant left over from gitleaks), so ASH drops it
rather than report a wrong version.

The scan path is ``.`` with the working directory at the source directory, so reported
paths are source-relative (``src/settings.py``), and an absolute path for the converted
target. Betterleaks exits 0 for a path that does not exist ("skipping error ... no such
file"), so it cannot be left to say that a target is missing; the template ``scan()``
skips a missing or empty target before it starts the tool.

Where Betterleaks differs from gitleaks
---------------------------------------
Measured on 1.10.1 (``cmd/root.go``, ``cmd/directory.go`` at the v1.10.1 tag, and runs
of the release binary):

* A ``.betterleaks.toml`` or ``.gitleaks.toml`` in the scanned tree is NOT read unless
  ``--unsafe-auto-load-config`` is passed, so there is nothing to defend against and
  ASH never passes it. Gitleaks reads ``.gitleaks.toml`` from its scan path by default,
  and ASH's gitleaks scanner writes a default-rules config to prevent that. Here the
  default is already the built-in rule set.
* The config environment variables are ``BETTERLEAKS_CONFIG`` and
  ``BETTERLEAKS_CONFIG_TOML``, with ``GITLEAKS_CONFIG`` and ``GITLEAKS_CONFIG_TOML``
  still read as the fallback of each. Precedence: ``--config``, then the path
  variable, then the TOML-content variable. A relative path variable is resolved
  against Betterleaks' working directory, the scanned tree, so ASH anchors it where
  the operator set it (``_resolve_config_file``).
* The ignore file is ``.betterleaksignore``, and ``.gitleaksignore`` still works. For
  each directory it looks in (the ``--gitleaks-ignore-path`` value and the scan path)
  it reads the first of the two that exists and not both. It reads the scan path's
  whatever ``--gitleaks-ignore-path`` says, which is the same as gitleaks.
* ``--version`` prints ``betterleaks version 1.10.1``.
* The default regular-expression engine is RE2, not Go's.
* ``betterleaks dir`` does no network calls: validation (live API checks of a found
  credential) is off unless ``--validation`` is passed, and ASH never passes it.

Ignore files
------------
``<scan path>/.betterleaksignore`` and ``.gitleaksignore`` list finding fingerprints
(``<file>:<rule>:<line>``). Betterleaks drops a listed finding before it writes the
report, so what they hide is neither reported nor counted as suppressed by ASH. Findings
are tuned with ASH suppressions, which are both, so the scanned tree does not configure
Betterleaks. There is no flag that turns the scan path's ignore file off (measured:
``--gitleaks-ignore-path`` pointing at an empty directory did not stop it).

So when the scan path holds either file, the scan fails before Betterleaks runs, naming
the file and the two ways out: move the entries to ASH suppressions, or set
``scanners.betterleaks.options.honor_tree_ignore_files`` in the operator's config (a
config outside every git checkout and the scanned directory, or ``--config-overrides``;
from a config inside the tree it is ignored with a warning). ASH's gitleaks scanner
re-scans the files such a file names to add its drops back; this plugin does not.

Inline allow comments
---------------------
``betterleaks:allow`` and ``gitleaks:allow`` comments drop a finding the same way, so
ASH passes ``--ignore-gitleaks-allow``. ``options.honor_inline_ignores: true`` turns
them back on, honored only when the operator set it.

Severity
--------
Betterleaks' SARIF results carry no ``level``. Every result is set to ``level: error`` and
``issue_severity: CRITICAL``, as gitleaks' are: every rule is "a credential of this kind
is present", and an exposed credential is the same severity whichever provider issued
it.

Exit status and output
----------------------
0 and 2 are success. Betterleaks' stderr is not copied into the scan's errors, and the
scan failure message names the log instead of quoting it: with ``honor_tree_ignore_files``
on, Betterleaks logs each ignore-file line it cannot parse, verbatim, and the line is
the scanned tree's text. Those log lines are cut after the message.

Offline
-------
Betterleaks' rules are compiled into the binary and ``dir`` makes no network call.

Sandbox
-------
The strict default: no network, and no variables or paths beyond the baseline, plus
one declaration for sandbox-exec: ``HOME`` is a private empty directory for the spawn,
because the regular-expression engine creates its compilation cache under it on macOS
and crashes when it cannot. The config environment variables and an operator ``config_file`` outside the tree are not
passed into a sandbox yet; grants derived from the environment or options wait for the
sandbox's grant gates.
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

from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base import scanner_operational_facets as opsf
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
from automated_security_helper.config.tool_config_trust import (
    empty_tool_directory,
    refuse_relative_extend_path,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.models.vocab import Severity, TargetType
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.config_trust import (
    LEADS_OUT_OF_THE_TREE,
    operator_path,
    refusal_warning,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.path_stat import is_anchored
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import active_scope
from automated_security_helper.utils.subprocess_utils import (
    OutputPreference,
    find_executable,
)

#: The text Betterleaks writes in place of a secret under ``--redact``.
REDACTED = "REDACTED"

#: Exit code Betterleaks is told to use when it finds leaks. See the module docstring.
LEAKS_EXIT_CODE = 2

#: Ignore files Betterleaks reads at the root of its scan path, in the order it
#: prefers them (the first that exists is read, not both).
IGNORE_FILE_NAMES = (".betterleaksignore", ".gitleaksignore")

#: Config names Betterleaks would read from the scanned tree with
#: ``--unsafe-auto-load-config``, which ASH never passes. Named only in the note logged
#: when one is present.
TREE_CONFIG_NAMES = (".betterleaks.toml", ".gitleaks.toml")

#: What Betterleaks logs, at WRN, before each ignore-file line it cannot parse, which it
#: then quotes. ``_mask_quoted_ignore_entries`` drops the quote.
INVALID_ENTRY_LOG = "Invalid .gitleaksignore entry"

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)


#: Environment variables Betterleaks reads a config from, in its order of precedence:
#: ``BETTERLEAKS_CONFIG`` and ``GITLEAKS_CONFIG`` name a file, ``BETTERLEAKS_CONFIG_TOML``
#: and ``GITLEAKS_CONFIG_TOML`` hold the config's text, and each ``GITLEAKS_`` name is
#: read only when its ``BETTERLEAKS_`` one is unset. When one is set, outside the scanner
#: sandbox, ASH leaves the TOML variables and an absolute path to Betterleaks, and passes
#: a path that is not absolute as ``--config`` anchored to the directory ASH runs in.
CONFIG_ENV_VARS = (
    "BETTERLEAKS_CONFIG",
    "BETTERLEAKS_CONFIG_TOML",
    "GITLEAKS_CONFIG",
    "GITLEAKS_CONFIG_TOML",
)


def _config_env_names_set() -> List[str]:
    """The names in ``CONFIG_ENV_VARS`` the operator set, in that order."""
    environ = snapshot_environ()
    return [name for name in CONFIG_ENV_VARS if environ.get(name)]


def _config_env_value() -> Optional[Tuple[str, str]]:
    """The config path variable Betterleaks would read, as ``(name, value)``, or None."""
    for name in _config_env_names_set():
        if not name.endswith("_TOML"):
            return name, snapshot_environ()[name]
    return None


def _config_env_read_name() -> Optional[str]:
    """The config variable Betterleaks reads, by its precedence, or None: the path
    variable ``_config_env_value`` names, else the first TOML variable set."""
    given = _config_env_value()
    if given is not None:
        return given[0]
    return next((n for n in _config_env_names_set() if n.endswith("_TOML")), None)


def _mask_quoted_ignore_entries(log_path: Path) -> None:
    """Remove what Betterleaks quotes from an ignore file in its log at ``log_path``.

    Betterleaks logs each line of the file it cannot parse as a fingerprint, verbatim
    (``WRN Invalid .gitleaksignore entry fingerprint=<line>``). The file is the scanned
    tree's, so the line can be anything the tree holds, a secret included. Each such
    log line is cut after the message; the rest of the log is kept.
    """
    try:
        fd = os.open(log_path, os.O_RDONLY | _NOFOLLOW | _BINARY)
    except OSError:
        return
    with os.fdopen(fd, "rb") as handle:
        text = handle.read().decode("utf-8", errors="replace")
    if INVALID_ENTRY_LOG not in text:
        return
    lines = [
        line[: line.index(INVALID_ENTRY_LOG) + len(INVALID_ENTRY_LOG)]
        + " (the entry Betterleaks quoted here was removed by ASH)"
        if INVALID_ENTRY_LOG in line
        else line
        for line in text.split("\n")
    ]
    with open_for_write(log_path, encoding="utf-8", errors="replace") as handle:
        handle.write("\n".join(lines))


class BetterleaksScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a Betterleaks TOML config. A relative path is taken from the "
                "directory of the config file that sets it, or from the working "
                "directory for --config-overrides, not from the source directory. Its "
                "rules and filters apply on top of ASH suppressions. "
                f"{SET_BY_THE_OPERATOR} Unset, Betterleaks uses BETTERLEAKS_CONFIG or "
                "BETTERLEAKS_CONFIG_TOML (or the GITLEAKS_ names of them) from the "
                "environment if one is set, else its default rules; a "
                ".betterleaks.toml or .gitleaks.toml in the scanned repository is "
                "not read. A path that does not exist fails the scan."
            ),
        ),
    ] = None
    honor_inline_ignores: Annotated[
        bool,
        Field(
            description=(
                "Honor inline `betterleaks:allow` and `gitleaks:allow` comments. Off "
                "by default: ASH runs `betterleaks --ignore-gitleaks-allow`, so every "
                "finding reaches ASH, where suppressions are reported and counted. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with a "
                "warning."
            ),
        ),
    ] = False
    honor_tree_ignore_files: Annotated[
        bool,
        Field(
            description=(
                "Run Betterleaks over a tree that holds a .betterleaksignore or "
                ".gitleaksignore, which Betterleaks always reads and which drops the "
                "findings it lists before ASH sees them, so they are neither reported "
                "nor counted as suppressed. Off by default: such a tree fails the scan "
                "before Betterleaks runs. Move the entries to ASH suppressions, or "
                f"turn this on. {SET_BY_THE_OPERATOR} Set by such a config, it is "
                "ignored with a warning."
            ),
        ),
    ] = False


class BetterleaksScannerConfig(ScannerPluginConfigBase):
    name: Literal["betterleaks"] = "betterleaks"
    enabled: bool = True
    options: Annotated[
        BetterleaksScannerConfigOptions,
        Field(description="Configure the betterleaks scanner"),
    ] = BetterleaksScannerConfigOptions()


@ash_scanner_plugin
class BetterleaksScanner(ScannerPluginBase[BetterleaksScannerConfig]):
    """Secret detection over the scan target's files using Betterleaks."""

    #: Not Python-only: Betterleaks is a native binary, installed from its pinned
    #: release asset, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    # Betterleaks' rules are compiled into the binary and `dir` makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name betterleaks' own SARIF (fixture
    #: tests/test_data/scanners/betterleaks/captured/positive.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result "ruleId"',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native severity) constant level error plus "
            'properties "issue_severity" CRITICAL, both set by _post_process_sarif',
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
            reason="betterleaks rules carry no CWE taxonomy in the SARIF",
        ),
        fingerprints=FacetDecl(
            state=FacetState.DROPPED,
            native_field='result "partialFingerprints" (commitSha, author, '
            "email, date, commitMessage)",
            reason="dir mode emits empty-string git metadata, which "
            "_post_process_sarif drops because an empty fingerprint is "
            "identical across every result; ASH runs only the dir subcommand, "
            "so no git metadata is ever kept",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="secret findings carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry id and shortDescription only",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="region.snippet.text, forced to REDACTED by "
            "--redact=100 and again by _post_process_sarif",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason="the SARIF rules carry id and shortDescription only; no "
            "reference URLs",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field='result properties "tags" (empty natively); the '
            "adapter appends secret and security",
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
            scanner_name="betterleaks",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.NONE,
                fetches=(),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.UNCHANGED,
                offline_strategy=OfflineStrategy.BUNDLED,
                sandbox_network=opsf.SandboxNetwork.NONE,
                source=(
                    "betterleaks_scanner.py offline_strategy, sandbox_requirements; "
                    "module header: `betterleaks dir` makes no network calls and ASH "
                    "never passes --validation"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=(),
                non_finding_artifacts=(),
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.SECRETS_CONTENTS,),
                tool_type=ScannerToolType.SECRETS,
                selection="`betterleaks dir` over the target; contents, not history (module header)",
                covers_note=(
                    "the alpha scanners declare no covers display string; no scanner "
                    "claims git-history secrets (UNCLAIMED_TARGET_KINDS)"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.PINNED_BINARY,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                tool_versions_key="betterleaks",
                python_only=False,
                use_uv_tool=False,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=opsf.PLATFORMS_ALL,
                note="asset table lists all six platform/arch pairs",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.CONSTANT,
                note="every finding is CRITICAL",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface=".betterleaksignore or .gitleaksignore in the scan root",
                        cite="betterleaks_scanner.py module header (Ignore files): the scan fails before the tool runs unless the operator sets options.honor_tree_ignore_files",
                    ),
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.NO,
                        surface="betterleaks:allow and gitleaks:allow comments; options.honor_inline_ignores turns them back on when the operator sets it",
                        cite="betterleaks_scanner.py module header (Inline allow comments): ASH passes --ignore-gitleaks-allow",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the git-metadata fingerprints are empty and dropped in dir mode; identity is file and line",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.OPERATOR_PATHS,
                env_prefixes=(),
                options_surface="an operator config file or TOML content, resolved against ASH's working directory; a repository-written config is ignored with a warning",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 2),
                semantics="ASH passes --exit-code=2 because the tool's default 1 means both leaks and some errors",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PINNED_RELEASE_BINARY,
                selection_surfaces=(
                    "ash_betterleaks_plugins in ash_plugin_modules",
                    "options.honor_tree_ignore_files",
                    "options.honor_inline_ignores",
                ),
                upstream_license=(
                    "MIT (source: utils/tool_downloads.py "
                    "THIRD_PARTY_LICENSES['betterleaks'], pinned commit 39d5bdc)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="no git repository is required and no history is read",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = {0, LEAKS_EXIT_CODE}
    # The strict default, plus one macOS declaration; see "Sandbox" in the module
    # docstring. The regular-expression engine (go-re2 over wazero) keeps a
    # compilation cache under os.UserCacheDir(), which on macOS is
    # $HOME/Library/Caches and cannot be moved with XDG_CACHE_HOME. sandbox-exec
    # denies that directory, and the engine then dereferences a nil module instead
    # of running without a cache. HOME is a private empty directory for the spawn,
    # so the cache can be created and is thrown away with it.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        sandbox_exec_cache_env=("HOME",),
    )

    # With honor_tree_ignore_files on, Betterleaks' stderr can quote the scanned
    # tree's ignore file (see _mask_quoted_ignore_entries), and the scanner
    # executor copies errors into the scan's results: the base class keeps the
    # stream out of both and out of the failure text. It stays in the log file.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "betterleaks"

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = BetterleaksScannerConfig()
        self.command = "betterleaks"
        self.subcommands = ["dir"]
        self.tool_type = ScannerToolType.SECRETS
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token Betterleaks would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "BetterleaksScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``."""
        self.custom_install_commands.update(pinned_tool_install_commands("betterleaks"))
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> BetterleaksScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, BetterleaksScannerConfigOptions):
            return options
        return BetterleaksScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("BetterleaksScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before Betterleaks runs whether it reads any file.

        Betterleaks is handed the whole target, walks it itself, and skips what its
        config's filters name. Any file it reads can hold a secret, so ASH makes no
        selection of its own that could come up empty. None means "cannot tell".
        """
        return None

    def _operator_config_path(self) -> Optional[Path]:
        """``options.config_file`` when the operator set it, else None (with a warning).

        Through ``config_trust.operator_path``, with ``outside_tree`` off: the operator
        may keep their own config in the tree.

        Raises:
            ScannerError: the operator's path is not a file, or is inside the scanned
                tree and leads out of it through a symlink.
        """
        value = self._options().config_file
        if not value:
            return None
        config = self.context.config if self.context is not None else None
        chosen = operator_path(
            config,
            "scanners.betterleaks.options.config_file",
            value,
            self._source_dir(),
            outside_tree=False,
        )
        if chosen.refusal == LEADS_OUT_OF_THE_TREE:
            raise ScannerError(
                f"scanners.betterleaks.options.config_file is {str(value)!r}, a path "
                "inside the scanned tree that resolves outside it through a symbolic "
                "link. The scanned repository decides what is at that path, so "
                "Betterleaks is not given it, and Betterleaks is not run."
            )
        if chosen.path is None:
            self._plugin_log(
                refusal_warning(
                    f"Ignoring scanners.betterleaks.options.config_file "
                    f"({str(value)!r}): {chosen.refusal}. Tune findings with ASH "
                    "suppressions.",
                    chosen.refusal,
                ),
                level=logging.WARNING,
            )
            return None
        if not chosen.path.is_file():
            raise ScannerError(
                f"scanners.betterleaks.options.config_file is {str(value)!r}, which is "
                f"not a file (resolved to {chosen.path.as_posix()}). Fix the path or "
                "unset the option; Betterleaks is not run without it."
            )
        return chosen.path

    def _honor_inline_ignores(self) -> bool:
        """Whether Betterleaks may apply ``betterleaks:allow`` comments in the tree."""
        if not self._options().honor_inline_ignores:
            return False
        return self._operator_gated(
            "scanners.betterleaks.options.honor_inline_ignores",
            True,
            False,
            "scanners.betterleaks.options.honor_inline_ignores is true in a "
            "config inside a git checkout or the scanned directory, or from an "
            "MCP client, so it is ignored: Betterleaks runs with "
            "--ignore-gitleaks-allow and allow comments do not apply; suppress "
            f"findings with ASH suppressions. {KEEP_A_SETTING}",
        )

    def _honor_tree_ignore_files(self) -> bool:
        """Whether a tree's ignore file may stand, when the operator said so."""
        if not self._options().honor_tree_ignore_files:
            return False
        return self._operator_gated(
            "scanners.betterleaks.options.honor_tree_ignore_files",
            True,
            False,
            "scanners.betterleaks.options.honor_tree_ignore_files is true in a "
            "config inside a git checkout or the scanned directory, or from an "
            "MCP client, so it is ignored: a tree that holds a .betterleaksignore "
            f"or .gitleaksignore still fails the scan. {KEEP_A_SETTING}",
        )

    def _resolve_config_file(self) -> Optional[Path]:
        """The config to pass as ``--config``; None leaves it to Betterleaks.

        The operator's ``options.config_file``. Otherwise a config path variable the
        operator set, passed as ``--config`` only when it is not anchored as given
        (absolute, and on Windows with a drive or share): Betterleaks would resolve
        it against its working directory, the scanned tree, so the repository would
        supply the config file. Anchored where the operator typed it instead. An
        absolute path, and a TOML-content variable, are left to Betterleaks. Without
        any, Betterleaks uses its built-in rules and reads no config from the tree
        (see the module docstring).
        """
        operator_config = self._operator_config_path()
        if operator_config is not None:
            refuse_relative_extend_path(
                "Betterleaks",
                "scanners.betterleaks.options.config_file",
                path=operator_config,
            )
            return operator_config
        set_vars = _config_env_names_set()
        if set_vars and active_scope() is not None:
            self._plugin_log(
                f"{', '.join(set_vars)} is not passed into the scanner sandbox; "
                "Betterleaks uses its default rules instead. Set "
                "scanners.betterleaks.options.config_file to choose a config.",
                level=logging.WARNING,
            )
        elif set_vars:
            # A relative extend path in the config would be opened from the
            # scanned tree, so each config variable that is set is read first.
            # Betterleaks opens only the one it reads by its precedence, so a byte
            # order mark is refused in that one alone.
            environ = snapshot_environ()
            read = _config_env_read_name()
            for name in set_vars:
                value = environ.get(name, "")
                if name.endswith("_TOML"):
                    refuse_relative_extend_path(
                        "Betterleaks", name, text=value, read_by_tool=name == read
                    )
                else:
                    # An absolute value is left to Betterleaks, which opens it as
                    # given, so it is checked as given: os.path.abspath would drop
                    # "link/.." by hand where the open follows the link first. Any
                    # other value is checked where ASH anchors it, the file passed.
                    refuse_relative_extend_path(
                        "Betterleaks",
                        name,
                        path=(
                            Path(value)
                            if is_anchored(value)
                            else Path(os.path.abspath(os.path.expanduser(value)))
                        ),
                        read_by_tool=name == read,
                    )
            given = _config_env_value()
            if given is not None and not is_anchored(given[1]):
                ASH_LOGGER.debug(
                    f"{given[0]} is not an absolute path; passing it to Betterleaks "
                    "resolved against the working directory ASH runs in"
                )
                return Path(os.path.abspath(os.path.expanduser(given[1])))
            ASH_LOGGER.debug(
                f"{', '.join(set_vars)} set; leaving Betterleaks config resolution "
                "to Betterleaks"
            )
            return None
        present = [n for n in TREE_CONFIG_NAMES if (self._source_dir() / n).is_file()]
        if present:
            self._plugin_log(
                f"{', '.join(present)} in the scanned tree is not read: Betterleaks "
                "runs with its default rules, so its findings are reported and tuned "
                "with ASH suppressions. Set scanners.betterleaks.options.config_file "
                "with --config-overrides or a config file outside every git checkout "
                "and the scanned directory to use a Betterleaks config.",
                level=logging.INFO,
            )
        return None

    def _refuse_tree_ignore_files(self, target: Path) -> None:
        """Fail before Betterleaks runs when the scan path holds an ignore file.

        See "Ignore files" in the module docstring. Any entry of either name counts,
        whatever it is (a file, a link, a directory): Betterleaks opens the name it
        finds first, and what it would read there is the tree's to decide.

        Raises:
            ScannerError: the scan path holds one and the operator did not accept it.
        """
        present = [
            name for name in IGNORE_FILE_NAMES if os.path.lexists(Path(target) / name)
        ]
        if not present or self._honor_tree_ignore_files():
            return
        raise ScannerError(
            f"The scanned tree holds {' and '.join(present)}. Betterleaks reads it "
            "whatever ASH passes and drops each finding it lists before ASH sees "
            "it, so those findings would be neither reported nor counted as "
            "suppressed, and Betterleaks is not run. Move its entries to ASH "
            "suppressions, or set scanners.betterleaks.options.honor_tree_ignore_files "
            "to true in a config outside every git checkout and the scanned "
            "directory (or with --config-overrides)."
        )

    def _empty_ignore_dir(self) -> Path:
        """A directory with no ignore file, for ``--gitleaks-ignore-path``.

        New and empty, outside the scanned tree, removed when the run ends
        (``empty_tool_directory``). Without the flag Betterleaks looks in its working
        directory, the scanned tree.
        """
        return empty_tool_directory(
            "ash-no-betterleaksignore", context=self.context
        ).resolve()

    def _scan_path(self, target: Path) -> str:
        """The path Betterleaks is given: ``.`` for the source, absolute otherwise.

        The source target as "." from the source directory (the subprocess's working
        directory), so reported paths are source-relative.
        """
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full Betterleaks argv for one target.

        Every option is one ``--flag=value`` token and the scan path follows ``--``, so
        no path or config value can be read as a flag.
        """
        args: List[str] = [
            self.command or "betterleaks",
            *self.subcommands,
            "--report-format=sarif",
            f"--report-path={results_file.as_posix()}",
            "--redact=100",
            f"--exit-code={LEAKS_EXIT_CODE}",
            "--no-banner",
            "--no-color",
            f"--gitleaks-ignore-path={self._empty_ignore_dir().as_posix()}",
        ]
        if not self._honor_inline_ignores():
            args.append("--ignore-gitleaks-allow")
        config_file = self._resolve_config_file()
        if config_file is not None:
            args.append(f"--config={config_file.as_posix()}")
        args.extend(["--", self._scan_path(target)])
        return args

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one Betterleaks run.

        ``global_ignore_paths`` is not translated into Betterleaks config: it is applied
        to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("BetterleaksScanner has no results directory")
        # ScannerExecutor runs this instance over the source and then the converted
        # target, and the base class keeps the worst exit code across runs. Without
        # this, a source run that failed (1) failed a clean converted run.
        self.exit_code = 0
        self._refuse_tree_ignore_files(target)
        # Absolute: Betterleaks runs with its working directory at the source
        # directory, and a library caller's relative output directory would have it
        # write the report there, where ASH does not read it.
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "betterleaks.sarif")
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
        """Refuse the report of a run Betterleaks did not finish.

        Exit 1 is a Betterleaks failure (see the module docstring), and any code
        outside 0 and 2 is not one it documents. Raised before reading so a partial
        report cannot pass as a complete one.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"betterleaks exited {self.exit_code}; it exits 0 when it finds "
                f"nothing and {LEAKS_EXIT_CODE} when it finds leaks, so this run failed"
            )
        return super()._read_results_file(results_file)

    def _run_subprocess(
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        stdout_preference: OutputPreference = "write",
        stderr_preference: OutputPreference = "write",
        cwd: Path | str | None = None,
        env: Dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Dict[str, Any]:
        """Run Betterleaks, then mask what its log quotes from an ignore file."""
        response = super()._run_subprocess(
            command,
            results_dir=results_dir,
            stdout_preference=stdout_preference,
            stderr_preference=stderr_preference,
            cwd=cwd,
            env=env,
            timeout=timeout,
        )
        if results_dir is not None:
            _mask_quoted_ignore_entries(
                Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
            )
        return response

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, then normalize every result
        (:meth:`normalize_results`)."""
        self._drop_results_under_output_dir(sarif_report, target)
        return self.normalize_results(sarif_report)

    @staticmethod
    def normalize_results(sarif_report: SarifReport) -> SarifReport:
        """Rate every result, tag it, drop empty fingerprints, keep snippets redacted.

        The result-level half of the adapter's post-processing, separated from
        the instance-bound half (output-directory dropping) so that conformance
        tests can drive betterleaks' own normalization over a committed capture
        without a scanner instance, the way ``CfnGuardScanner.normalize_results``
        is driven. Pure over the report: no tool is run and nothing outside the
        report is read.
        """
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
            setattr(  # noqa: B010
                result.properties, "issue_severity", Severity.CRITICAL.value
            )

            for location in result.locations or []:
                physical = location.physicalLocation
                region = physical.root.region if physical else None
                snippet = region.snippet if region else None
                if snippet is not None and snippet.text not in (None, REDACTED):
                    snippet.text = REDACTED

            # Betterleaks fills commitSha/author/email/date/commitMessage with empty
            # strings in dir mode. An empty fingerprint is identical across every
            # result, so it is dropped rather than passed on.
            fingerprints = result.partialFingerprints
            if fingerprints:
                kept = {k: v for k, v in fingerprints.items() if v not in ("", None)}
                result.partialFingerprints = kept or None

        run = sarif_report.runs[0] if sarif_report.runs else None
        if run is not None and run.tool and run.tool.driver:
            # Betterleaks 1.10.1 writes semanticVersion "v8.0.0" whatever its real
            # version; leave it out rather than report a wrong one.
            run.tool.driver.semanticVersion = None
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "betterleaks")
        if not found:
            ASH_LOGGER.warning(
                "betterleaks executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_betterleaks_plugins\"]' --tool betterleaks`."
            )
        return found is not None


__all__ = [
    "BetterleaksScanner",
    "BetterleaksScannerConfig",
    "BetterleaksScannerConfigOptions",
    "IGNORE_FILE_NAMES",
    "LEAKS_EXIT_CODE",
    "TREE_CONFIG_NAMES",
]
