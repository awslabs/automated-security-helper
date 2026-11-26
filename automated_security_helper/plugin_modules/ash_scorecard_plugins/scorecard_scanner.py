# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ScorecardScanner: OpenSSF Scorecard as an ASH alpha scanner.

What it runs
------------
``scorecard --repo=<github.com/owner/repo> --format=json --show-details``, once
per scan, and converts the JSON it prints on stdout into SARIF. The flags are
the ones documented in the OpenSSF Scorecard README and ``options/flags.go``
(``--repo``, ``--format`` with ``default`` and ``json``, ``--show-details``);
the JSON shape is ``JSONScorecardResultV2`` in ``pkg/scorecard/json.go``:
``date``, ``repo{name,commit}``, ``scorecard{version,commit}``, ``score``,
``checks[{name,score,reason,details[],documentation{url,short}}]``,
``metadata``. Scorecard has no SARIF output outside its GitHub action, so this
is a conversion, as for guarddog.

THE POSTURE OF THE ORIGIN REPOSITORY, NOT THE CHECKOUT
------------------------------------------------------
Scorecard scores the repository **as it is hosted on GitHub**: branch
protection, code review, maintainers, signed releases, token permissions of the
workflows on the default branch, and so on. It does not score the files ASH is
scanning. A dirty working tree, an unpushed branch or a local edit changes
nothing in the result, and a clean checkout of a poorly protected repository
still reports findings. ``--local`` (file-based checks only) is deliberately not
used: it would cover a different, smaller set of checks, and the point of this
plugin is the hosted posture. Every finding says so in its message.

Opt-in, fail closed
-------------------
Like ``snyk-code``, Scorecard needs a network and a credential, so the scanner:

* is **disabled by default** (``enabled: false``); turn it on with
  ``scanners.scorecard.enabled: true`` once the module is listed;
* declares ``offline_strategy = SKIP_OFFLINE`` and a sandbox that grants the
  network and passes the GitHub token variables through;
* refuses to run, with a message that names the missing piece, when ASH is
  offline, when none of ``GITHUB_AUTH_TOKEN``, ``GITHUB_TOKEN``,
  ``GH_AUTH_TOKEN`` or ``GH_TOKEN`` is set (Scorecard has no ``--token`` flag;
  the README names these variables), or when no ``github.com/<owner>/<repo>``
  can be determined. The repository is the ``repo`` option, else the ``url`` of
  ``[remote "origin"]`` in ``<source>/.git/config``. Other hosts are refused:
  this plugin is GitHub only.

Severity
--------
Scorecard rates each check 0 to 10 (10 best) or -1 when it could not decide.
A check at 10 is not a finding. A check at -1 is not a finding either; it is
counted in the log. Otherwise::

    score 0-2  -> HIGH    / error
    score 3-5  -> MEDIUM  / warning
    score 6-9  -> LOW     / note

The ceiling is HIGH, not CRITICAL: these are posture findings about how a
project is run, not exploitable vulnerabilities. ``issue_severity`` and the
SARIF level are set together from one table (``SCORE_BANDS``). The aggregate
``score`` is reported in the run properties and is never a finding.

Location
--------
A check result names no file: it is about the hosted repository. Each result's
location is that repository, ``github.com/<owner>/<name>``, written as the
artifact URI, so an ASH suppression matches it by ``rule_id`` (the check name)
and ``path`` (the repository), and a code-scanning upload has a location to
show. It is not a path in the scanned tree; no region is written.

Exit status and output
----------------------
Scorecard's exit codes are not documented; the source says a repository it
could not scan, or a check that failed at run time, makes it exit non-zero.
Measured on v5.7.0: a check that fails at run time makes it exit 1 with the
whole JSON document still on stdout, that check at -1 and its error as the
reason (``tests/test_data/scanners/scorecard/captured/check-error.json``).
Only 0 is accepted (``success_exit_codes = {0}``); any other code fails the
scan, so such a run is not read as a partial result. A timeout, empty stdout,
output that is not JSON, output that is not a Scorecard result object, and a
check with a missing name or an out-of-range score all fail the scan rather
than read as clean. Scorecard's stderr can quote what GitHub answered, so
``quote_tool_stderr`` is False: the base class keeps the stream out of
``self.errors`` and out of the failure text, and it stays in the scanner's
stderr log file in the results directory.

Installation
------------
ASH pins Scorecard v5.7.0 in this plugin's own install module
(``scorecard_install.py``: the version, one release asset per platform, a
SHA256 for each archive and for the executable inside it), so
``ash dependencies install`` places the pinned binary when the module is
listed, and the ASH container image installs it the same way. A ``scorecard``
already on ``PATH`` is used as found. Scorecard is Apache-2.0 licensed.

Template or own scan()
----------------------
Scorecard writes its report to stdout, so the template flow (which reads a
results file the tool writes) does not fit; this scanner overrides ``scan()``
as hadolint and guarddog do.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

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
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.plugin_modules.ash_scorecard_plugins.scorecard_install import (
    scorecard_install_commands,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The variables Scorecard reads a GitHub token from (README, "Authentication").
TOKEN_ENV_NAMES = ("GITHUB_AUTH_TOKEN", "GITHUB_TOKEN", "GH_AUTH_TOKEN", "GH_TOKEN")

#: Variables removed from Scorecard's environment because they redirect it to
#: another host or enable behavior ASH has not measured (``GH_HOST`` points it at a
#: GitHub Enterprise host, ``SCORECARD_EXPERIMENTAL`` is read in ``cmd/root.go``).
_REMOVED_ENV_VARS = frozenset({"GH_HOST", "SCORECARD_EXPERIMENTAL", "GL_HOST"})

#: ``(lowest score, highest score, ASH severity, SARIF level)``. One table, so the
#: severity and the level cannot disagree. See "Severity" in the module docstring.
SCORE_BANDS: Tuple[Tuple[int, int, str, str], ...] = (
    (0, 2, "HIGH", "error"),
    (3, 5, "MEDIUM", "warning"),
    (6, 9, "LOW", "note"),
)

# A GitHub owner (user or organization) is letters, digits and hyphens: no dot and
# no underscore. A dot in the first segment is what makes ``github.com/o`` read as
# owner ``github.com`` and name ``o`` in the short form, so the owner class has none.
# A repository name may also hold dots and underscores.
_REPO_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
_SHORT_REPO_RE = re.compile(r"^(?P<owner>[A-Za-z0-9-]+)/(?P<name>[A-Za-z0-9_.-]+)$")
_SCP_REMOTE_RE = re.compile(
    r"^(?:ssh://)?git@github\.com[:/](?P<owner>[A-Za-z0-9-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)

_POSTURE_NOTE = (
    "This scores the origin repository as hosted on GitHub, not the files that were "
    "scanned."
)


def severity_for_score(score: int) -> Tuple[str, str]:
    """``(ASH severity, SARIF level)`` for a check score of 0 to 9.

    Raises:
        ValueError: for 10 (not a finding), -1 (inconclusive) or anything else.
    """
    for low, high, severity, level in SCORE_BANDS:
        if low <= score <= high:
            return severity, level
    raise ValueError(f"score {score} is not one a finding is reported for")


def normalize_repo(value: str) -> Optional[str]:
    """``github.com/<owner>/<name>`` for a GitHub repository spelling, else None.

    Accepts ``owner/name``, ``github.com/owner/name``, ``https://github.com/...`` and
    the ``git@github.com:owner/name.git`` remote form. Any other host, an owner with
    a character outside ``[A-Za-z0-9-]`` (a dotted first segment such as
    ``github.com/o`` is a host, not an owner) and a name with one outside
    ``[A-Za-z0-9_.-]`` is None.
    """
    text = (value or "").strip()
    for pattern in (_REPO_RE, _SCP_REMOTE_RE, _SHORT_REPO_RE):
        match = pattern.match(text)
        if match:
            owner, name = match.group("owner"), match.group("name")
            if owner in (".", "..") or name in (".", ".."):
                return None
            return f"github.com/{owner}/{name}"
    return None


def origin_url_from_git_config(source_dir: Path) -> Optional[str]:
    """The ``url`` of ``[remote "origin"]`` in ``<source_dir>/.git/config``, or None.

    Read as text and parsed by hand: no ``git`` process is started in a tree whose
    configuration the scanned repository controls. A ``.git`` that is a file (a
    worktree or submodule) is not followed; set the ``repo`` option there.
    """
    config = Path(source_dir) / ".git" / "config"
    try:
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    in_origin = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_origin = re.fullmatch(r'\[remote\s+"origin"\]', line) is not None
            continue
        if in_origin and "=" in line:
            key, _, value = line.partition("=")
            if key.strip().lower() == "url":
                return value.strip()
    return None


class ScorecardScannerConfigOptions(ScannerOptionsBase):
    repo: Annotated[
        str | None,
        Field(
            description=(
                "The GitHub repository to score: `owner/name`, `github.com/owner/name` "
                "or an https URL. Unset, the `url` of the `origin` remote in "
                "`<source>/.git/config` is used. Scorecard scores this repository as "
                "hosted on GitHub, not the files ASH scans. Only github.com is "
                "supported; any other host fails the scan."
            ),
        ),
    ] = None


class ScorecardScannerConfig(ScannerPluginConfigBase):
    name: Literal["scorecard"] = "scorecard"
    # Off until an operator turns it on: it needs a network and a GitHub token and
    # scores the origin repository, not the checkout. See the module docstring.
    enabled: bool = False
    options: Annotated[
        ScorecardScannerConfigOptions,
        Field(description="Configure the scorecard scanner"),
    ] = ScorecardScannerConfigOptions()


@ash_scanner_plugin
class ScorecardScanner(ScannerPluginBase[ScorecardScannerConfig]):
    """OpenSSF Scorecard posture of the origin GitHub repository."""

    #: A native binary, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    #: Scorecard calls the GitHub API; nothing is bundled.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    #: Scorecard's exit codes are undocumented; 0 is the only one read as a finished run.
    success_exit_codes: ClassVar[Set[int]] = {0}
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        env_names=TOKEN_ENV_NAMES,
    )

    # Scorecard's stderr can quote what GitHub answered, and the scanner executor
    # copies errors into the scan's results: the base class keeps the stream out of
    # both and out of the failure text. It stays in the stderr log file.
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "scorecard"

    #: The facets register row (base/scanner_facets.py). Declaration only. The
    #: native output is Scorecard's own JSON (``JSONScorecardResultV2``), converted
    #: to SARIF by ``convert_scorecard_result``. The corpus is a real v5.7.0 run
    #: (tests/test_data/scanners/scorecard/captured/, see its README): the same
    #: document a ``--repo`` run prints, from the file-based checks of a local run,
    #: because a ``--repo`` run needs a GitHub token. tests/unit/plugin_modules/
    #: ash_scorecard_plugins/data/scorecard_result.json is a schema-derived sample
    #: with a check at every band edge, not a capture.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='checks[].name (e.g. "Branch-Protection")',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field="checks[].score (0 to 10), banded by SCORE_BANDS: 0-2 "
            "HIGH, 3-5 MEDIUM, 6-9 LOW; 10 and -1 are not findings",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="the scored repository (repo.name, the --repo value: "
            "github.com/<owner>/<name>), written as each result's artifact URI; "
            "a hosted repository, not a path in the scanned tree, which a "
            "suppression's path matches",
        ),
        line_range=FacetDecl(
            state=FacetState.NA,
            reason="a result locates the hosted repository, not a line",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="a result locates the hosted repository, not a column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field="checks[].reason and checks[].details[], assembled with "
            "the score and the origin-repository note by the adapter",
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="the hosted repository locator is not an infrastructure or "
            "deployable resource id, and a wrong value would bind a "
            "resource-scoped suppression to the wrong finding",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="findings are about how a repository is run, not about a "
            "deployable resource",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="findings name a repository check, not a package",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="findings name a repository check, not a package",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="findings name a repository check, not a package",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="posture checks carry no CVE taxonomy",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="posture checks carry no CWE taxonomy",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field='partialFingerprints["scorecard/v1"], a sha256 the '
            "adapter computes over the repository and the check name (not a "
            "native field)",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="posture checks carry no fix state",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the JSON carries no remediation text; only a documentation "
            "link, which is the reference",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="posture checks have no code snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field="checks[].documentation.url, written as the rule helpUri "
            "when it is https",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="rule-level tags scorecard and supply-chain, written by "
            "the adapter",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties scorecard_score and scorecard_repo; "
            "run property scorecard_aggregate_score from the document's score",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py).
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="scorecard",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.PLATFORM_POLICIES,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "Scorecard reads the repository's settings (branch protection, "
                    "reviews, workflow permissions) from the GitHub API, so an "
                    "offline run is refused and the scanner is skipped"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "scorecard_scanner.py offline_strategy, sandbox_requirements "
                    "(network plus the four GitHub token variables) and _gate_refusal"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="Scorecard's own JSON (JSONScorecardResultV2) on stdout, "
                "converted to SARIF by convert_scorecard_result",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.PACKAGE_SOURCES,),
                tool_type=ScannerToolType.SCA,
                selection=(
                    "the origin repository as hosted on GitHub (options.repo, else "
                    "the origin remote in <source>/.git/config), not the files ASH "
                    "scans; one invocation per scan, the converted target is not "
                    "rescored"
                ),
                covers_note="an alpha scanner; it declares no covers display string",
                tool_type_note=(
                    "no target kind in the register names a hosted repository; SCA "
                    "is the nearest type (supply-chain checks such as Pinned-"
                    "Dependencies, Dependency-Update-Tool and Vulnerabilities), and "
                    "package_sources the nearest kind"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: no runtime-compatibility rows were measured for Scorecard.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="installed by the plugin's own pinned installer "
                "(scorecard_install.py: linux, darwin and windows, each amd64 and "
                "arm64), not by the shared tool_downloads table, so the register "
                "lists none",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.DERIVED,
                note="the 0-10 check score is banded by ASH (SCORE_BANDS); the "
                "ceiling is HIGH because these are posture findings",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(),
                none_reason="Scorecard scores the hosted repository and reads no "
                "ignore file from the scanned tree; ASH suppressions by rule are "
                "the surface",
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="a computed sha256 under scorecard/v1 over repository and check",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="typed option repo; the checks are Scorecard's own",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0,),
                semantics="Scorecard's exit codes are undocumented; only 0 is read "
                "as a finished run and any other code fails the scan. v5.7.0 exits "
                "1, with the whole JSON document on stdout, when a check fails at "
                "run time (measured; captured/check-error.json)",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_scorecard_plugins in ash_plugin_modules",
                    "scanners.scorecard.enabled (off by default)",
                ),
                upstream_license="Apache-2.0 (source: the LICENSE file inside the "
                "v5.7.0 release archives, byte-identical to the repository's "
                "LICENSE at the tag commit d7552fb3, read 2026-11-26; the binary is "
                "downloaded and never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.AUTH_TOKEN, opsf.Prerequisite.GIT_CHECKOUT),
                note="a GitHub token in GITHUB_AUTH_TOKEN, GITHUB_TOKEN, "
                "GH_AUTH_TOKEN or GH_TOKEN, and a github.com origin remote unless "
                "options.repo is set",
            ),
        )
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ScorecardScannerConfig()
        self.command = "scorecard"
        self.tool_type = ScannerToolType.SCA
        # The argv is assembled in _build_arguments.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "ScorecardScanner":
        """Install from the pinned release asset in ``scorecard_install.py``.

        The pin is module-local: ``utils/tool_downloads.py`` has no Scorecard download
        table (only its license entry). This table never raises, so constructing the
        scanner during a scan cannot fail on it.
        """
        self.custom_install_commands.update(scorecard_install_commands())
        return self

    # ------------------------------------------------------------------
    # The opt-in gate
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        """The plugin context; the base class refuses to construct without one."""
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("ScorecardScanner has no plugin context")
        return self.context

    def _options(self) -> ScorecardScannerConfigOptions:
        options = getattr(self.config, "options", None)
        if isinstance(options, ScorecardScannerConfigOptions):
            return options
        return ScorecardScannerConfigOptions.model_validate(
            options.model_dump() if hasattr(options, "model_dump") else {}
        )

    @staticmethod
    def _token_present() -> bool:
        environ = snapshot_environ()
        return any(environ.get(name) for name in TOKEN_ENV_NAMES)

    def _resolve_repo(self) -> Tuple[Optional[str], Optional[str]]:
        """``(github.com/owner/name, None)`` or ``(None, why not)``."""
        configured = self._options().repo
        if configured:
            repo = normalize_repo(configured)
            if repo is None:
                return None, (
                    "the repo option is not a github.com repository "
                    "(owner/name, github.com/owner/name or an https URL); only "
                    "github.com is supported"
                )
            return repo, None
        url = origin_url_from_git_config(Path(self._ctx.source_dir))
        if not url:
            return None, (
                "no `origin` remote was found in the source directory's .git/config; "
                "set scanners.scorecard.options.repo to owner/name"
            )
        repo = normalize_repo(url)
        if repo is None:
            return None, (
                "the origin remote is not a github.com repository; only github.com "
                "is supported. Set scanners.scorecard.options.repo to owner/name"
            )
        return repo, None

    def _gate_refusal(self) -> Optional[str]:
        """Why the scan must not start, or None. Checked in this order."""
        if self._is_offline_mode():
            return "ASH is offline and Scorecard needs the GitHub API"
        if not self._token_present():
            return (
                "no GitHub token is set; set one of "
                f"{', '.join(TOKEN_ENV_NAMES)} (Scorecard has no --token flag)"
            )
        _, why = self._resolve_repo()
        return why

    def _is_offline_mode(self) -> bool:
        from automated_security_helper.core.constants import is_offline_mode

        if is_offline_mode():
            return True
        try:
            return bool(self._scanner_offline())
        except Exception:
            return False

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        refusal = self._gate_refusal()
        if refusal is not None:
            self.dependency_unavailable_reason = f"scorecard is not run: {refusal}"
            ASH_LOGGER.warning(self.dependency_unavailable_reason)
            return False
        found = find_executable(self.command or "scorecard")
        if not found:
            self.dependency_unavailable_reason = (
                "scorecard executable not found in PATH. Install the pinned release "
                "with `ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_scorecard_plugins\"]' --tool scorecard`."
            )
            ASH_LOGGER.warning(self.dependency_unavailable_reason)
        return found is not None

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _build_arguments(self, repo: str) -> List[str]:
        """One ``--flag=value`` token per option; no positional argument."""
        return [
            self.command or "scorecard",
            f"--repo={repo}",
            "--format=json",
            "--show-details",
        ]

    @staticmethod
    def _subprocess_env() -> Dict[str, str]:
        return {
            k: v for k, v in snapshot_environ().items() if k not in _REMOVED_ENV_VARS
        }

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: scorecard overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def _empty_report(self) -> SarifReport:
        return convert_scorecard_result(
            {"checks": [], "scorecard": {"version": self.tool_version}},
            repo="github.com/unknown/unknown",
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: ScorecardScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Score the origin repository once; the converted target is not rescored."""
        self.targets_attempted = 0
        self.targets_failed = 0

        if target_type != "source":
            # The origin repository does not depend on the converted tree.
            return self._empty_report()

        # The gate is read before _pre_scan, which returns False (a skipped,
        # missing-dependency scan) when validate_plugin_dependencies refuses: an
        # enabled scanner that cannot run must fail the scan and say why, not read
        # as skipped.
        refusal = self._gate_refusal()
        if refusal is not None:
            self.targets_failed = 1
            raise ScannerError(f"scorecard was not run: {refusal}")

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file: Optional[Path] = None
        try:
            repo, why = self._resolve_repo()
            if repo is None:
                raise ScannerError(f"scorecard was not run: {why}")
            self.targets_attempted = 1

            results_dir = Path(self.results_dir).joinpath(target_type)
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("scorecard.sarif")
            results_file.unlink(missing_ok=True)

            final_args = self._build_arguments(repo)
            response = self._run_subprocess(
                command=final_args,
                results_dir=results_dir,
                stdout_preference="return",
                stderr_preference="write",
                env=self._subprocess_env(),
                timeout=self._effective_scan_timeout(),
            )
            response = response if isinstance(response, dict) else {}
            self._post_scan(target=target, target_type=target_type)

            if response.get("timed_out"):
                raise ScannerError(
                    f"scorecard timed out after {self._effective_scan_timeout()}s "
                    "and was killed, so it produced no report. Raise "
                    "scanners.scorecard.options.scan_timeout if needed."
                )
            if self.exit_code not in self.success_exit_codes:
                raise ScannerError(
                    f"scorecard exited {self.exit_code}; only 0 is a finished run. "
                    "Its stderr is in the scanner's stderr log in the results "
                    "directory and is not quoted here."
                )
            document = self._parse_json(response)
            report = convert_scorecard_result(document, repo=repo)
            self.targets_failed = 0
            with open_for_write(results_file) as handle:
                handle.write(
                    report.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            version = (document.get("scorecard") or {}).get("version")
            if isinstance(version, str) and version:
                self.tool_version = version
            self._inject_invocation(report, final_args, target)
            return report
        except Exception as e:
            self.targets_failed = max(self.targets_failed, 1)
            raise ScannerError(self._describe_scan_failure(e, results_file))

    @staticmethod
    def _parse_json(response: Dict[str, Any]) -> Dict[str, Any]:
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            raise ScannerError("scorecard exited 0 but wrote no report")
        try:
            document = json.loads(stdout)
        except ValueError as exc:
            raise ScannerError(f"scorecard's output is not JSON ({exc})") from exc
        if not isinstance(document, dict) or not isinstance(
            document.get("checks"), list
        ):
            raise ScannerError("scorecard's output is not a Scorecard result object")
        return document


def convert_scorecard_result(document: Dict[str, Any], *, repo: str) -> SarifReport:
    """Convert one Scorecard JSON document (V2) into a SARIF report.

    One result per check scored 0 to 9; ``repo`` (``github.com/owner/name``) is the
    result's location. A check at 10 or -1 yields no result.

    Raises:
        ScannerError: a check that is not an object, has no name, or has a score
            that is not an integer from -1 to 10.
    """
    results: List[Dict[str, Any]] = []
    rules: Dict[str, Dict[str, Any]] = {}
    inconclusive: List[str] = []
    for check in document.get("checks") or []:
        if not isinstance(check, dict):
            raise ScannerError("scorecard reported a check that is not an object")
        name = check.get("name")
        score = check.get("score")
        if not isinstance(name, str) or not name:
            raise ScannerError("scorecard reported a check with no name")
        if (
            isinstance(score, bool)
            or not isinstance(score, int)
            or not -1 <= score <= 10
        ):
            raise ScannerError(
                f"scorecard reported check {name} with a score that is not an "
                f"integer from -1 to 10: {score!r}"
            )
        if score == -1:
            inconclusive.append(name)
            continue
        if score == 10:
            continue
        severity, level = severity_for_score(score)
        reason = check.get("reason") if isinstance(check.get("reason"), str) else ""
        details = [d for d in (check.get("details") or []) if isinstance(d, str)]
        doc = check.get("documentation")
        doc = doc if isinstance(doc, dict) else {}
        url = doc.get("url") if isinstance(doc.get("url"), str) else None
        short = doc.get("short") if isinstance(doc.get("short"), str) else name
        if name not in rules:
            rule: Dict[str, Any] = {
                "id": name,
                "shortDescription": {"text": short},
                "properties": {"tags": ["scorecard", "supply-chain"]},
            }
            if url and url.startswith("https://"):
                rule["helpUri"] = url
            rules[name] = rule
        text = f"{name} scored {score}/10: {reason}".rstrip(": ")
        text += f" {_POSTURE_NOTE}"
        if details:
            text += " Details: " + "; ".join(details[:5])
            if len(details) > 5:
                text += f"; and {len(details) - 5} more"
        fingerprint = hashlib.sha256(f"{repo}|{name}".encode()).hexdigest()[:32]
        results.append(
            {
                "ruleId": name,
                "level": level,
                "message": {"text": text},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": repo}}}
                ],
                "partialFingerprints": {"scorecard/v1": fingerprint},
                "properties": {
                    "issue_severity": severity,
                    "scorecard_score": score,
                    "scorecard_repo": repo,
                },
            }
        )
    if inconclusive:
        ASH_LOGGER.info(
            "scorecard could not decide these checks (score -1), so they are not "
            f"findings: {', '.join(inconclusive)}"
        )
    aggregate = document.get("score")
    driver: Dict[str, Any] = {
        "name": "OpenSSF Scorecard",
        "informationUri": "https://github.com/ossf/scorecard",
        "rules": list(rules.values()),
    }
    version = (document.get("scorecard") or {}).get("version")
    if isinstance(version, str) and version:
        driver["version"] = version
    run: Dict[str, Any] = {"tool": {"driver": driver}, "results": results}
    if isinstance(aggregate, (int, float)) and not isinstance(aggregate, bool):
        run["properties"] = {"scorecard_aggregate_score": aggregate}
    return SarifReport.model_validate({"version": "2.1.0", "runs": [run]})


__all__ = [
    "SCORE_BANDS",
    "ScorecardScanner",
    "ScorecardScannerConfig",
    "ScorecardScannerConfigOptions",
    "convert_scorecard_result",
    "normalize_repo",
    "origin_url_from_git_config",
    "severity_for_score",
]
