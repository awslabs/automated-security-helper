# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The builtin ``trivy`` scanner: ``trivy fs``, vulnerabilities by default.

What it runs
------------
``trivy fs`` over each scan target, SARIF out. ``fs`` rather than the community
plugin's ``repository``: ASH hands every scanner a directory, and ``fs`` is trivy's
command for a local directory (the converted target, for one, is never a git
checkout).

Which trivy scanners, and why only ``vuln`` by default
------------------------------------------------------
trivy can run four scanners. ASH already runs a default scanner for three of the
four questions, so this scanner runs only the one whose answer comes from trivy's
own data:

* ``vuln`` (on): known vulnerabilities in dependency manifests and lockfiles,
  matched against trivy's vulnerability database. grype answers the same question
  from a different database, and the two disagree often enough (different
  advisory sources and matchers) that a second opinion is the reason to enable
  trivy at all.
* ``secret`` (off): detect-secrets is a default ASH scanner. Running trivy's
  secret rules as well reports the same credential twice under two rule ids, and
  a suppression written for one does not cover the other.
* ``misconfig`` (off): checkov, cfn-nag and cdk-nag already cover IaC, with ASH's
  suppressions and policy tooling built around their rule ids.
* ``license`` (off): a license is a compliance question, not a vulnerability, and
  its verdicts depend on a license policy ASH does not hold. ``license_full``
  (scan source headers too) is off with it, since it slows a scan for findings
  nobody asked for.

Any of the four can be turned on with ``scanners.trivy.options.scanners``, by the
operator: ``--config-overrides`` or a config file outside the scanned tree
(``utils/config_trust.set_by_operator``). Set from a config in the scanned tree,
any set but the default is ignored with a warning, and trivy runs ``vuln``: a
repository could otherwise turn ``vuln`` off (``scanners: [license]``) and its
vulnerability findings, and the database check, would vanish with nothing in the
report saying so.

``ignore_unfixed`` defaults to False, unlike ``trivy-repo``: a vulnerability with
no fixed version is still a vulnerability, and grype reports them by default. ASH
already warns when a grype config withholds unfixed matches; setting
``ignore_unfixed: true`` here gets the same warning.

Vulnerability database and staleness
------------------------------------
The database is ``trivy-db`` in ``utils/content_databases.py`` and is held to its
bound exactly the way grype's is: after the scan, the executor reads the
database's own ``UpdatedAt`` through ``utils/content_db_staleness.py`` and fails
the scan (or warns, under ``content_db_staleness: warn``) when it is past the
declared 24h.

* Online, ASH updates the database once per scan before trivy runs, outside the
  scanner sandbox and under a lock (``TrivyScannerBase._shared_update_flags``,
  ``utils/content_db_refresh.py``), and the scan fails if that update does. trivy
  then runs with ``--skip-db-update`` against the database the update wrote.
  trivy's own rule (a database past its ``NextUpdate`` is replaced) is the
  registry's 24h bound, so the post-scan check agrees with it. When the operator
  turns trivy's update off (``TRIVY_SKIP_DB_UPDATE``, or ``db.skip-update`` in an
  honored ``config_file``), ASH's update is left out with a warning and trivy reads
  the cached database as it is; the post-scan check still holds it to the bound.
* Offline, ASH passes ``--skip-db-update`` (with ``--skip-java-db-update`` and
  ``--skip-check-update``), which makes trivy use any database it has. The
  post-scan check is what holds that database to the bound. With no database at
  all trivy cannot scan offline, so the scanner reports MISSING with the reason
  before trivy runs.
* Online or offline, trivy scans never contact package registries: every scan
  gets ``--offline-scan`` (``SCAN_FLAGS`` in ``_trivy_scanner_base.py``), and the
  database refresh is the separate step above. Every scan also gets
  ``--skip-version-check``, so trivy does not ask about new versions either.

The database is only read by ``vuln``. With ``vuln`` turned off nothing is
measured and the offline database check is skipped.

Severity
--------
Each result's ASH severity is trivy's own severity for it (CRITICAL, HIGH, MEDIUM,
LOW), read from the ``Severity:`` line trivy writes in the result's message.
Without this, ASH would bucket the rule's ``security-severity`` (a CVSS base
score), and a finding trivy rates HIGH with a 6.5 CVSS score would be reported
MEDIUM. A result whose severity is UNKNOWN keeps ASH's generic SARIF mapping (the
CVSS score, then the SARIF level).

``severity_threshold`` is not passed to trivy as ``--severity``, which would drop
every lower finding before ASH saw it, so that it was neither reported nor
counted. ASH applies the threshold after the scan, as for every scanner, to the
severity above: a finding below it is reported and does not fail the scan.

Per result, not per rule: trivy writes one SARIF rule per CVE and rewrites its
severity tag (and ``security-severity``) for each result, so the rule ends up with
the last result's. One CVE can be rated differently for two packages in one scan:
measured with 0.75.0 on a Debian tree, CVE-2014-9939 is CRITICAL for binutils and
LOW for gdb, and its rule says LOW. Only a result with no severity line of its own
(trivy writes none for a license finding, whose rule is per package and license)
takes its rule's tag, and only when the result's own SARIF level agrees with it.

trivy configuration in the scanned repository
---------------------------------------------
trivy runs with the scanned repository as its working directory, where it reads
``trivy.yaml``, ``.trivyignore`` and (for ``secret``) ``trivy-secret.yaml`` by
default. Measured on v0.69.3 against the fixture repository (10 findings): a
``.trivyignore`` line dropped its finding, ``severity: [CRITICAL]`` in
``trivy.yaml`` dropped all 10, and ``scan.skip-files`` dropped all 10 with exit 0.
A scanned repository should not be able to quietly shape its own report, so ASH
passes ``--config``, ``--ignorefile`` and ``--secret-config`` pointing at files of
its own that set nothing. ``config_file``, ``ignore_file`` and
``secret_config_file`` opt in to real ones, each honored only from the operator and
only for a file outside the scanned tree (``TrivyScannerBase._operator_path``): a
trivy.yaml can also load WASM modules (``module.dir``), and the other two drop
findings. ``trivy-repo`` passes its own ``--config``, ``--module-dir``,
``--ignorefile`` and ``--secret-config`` under the same rule, and both scanners take
the last two from ``TrivyScannerBase._trivy_input_file``, which falls back to
``TRIVY_IGNOREFILE`` and ``TRIVY_SECRET_CONFIG`` for a file outside the tree. The
database update runs from outside the tree with an explicit ``--config``
(``TrivyScannerBase._shared_update_flags``). trivy 0.75.0 reads nothing else from a
default location: ``--ignore-policy`` (a Rego file) has none, and an ignore policy
named by the tree's ``trivy.yaml`` does not apply because that file is not read
(``tests/integration/scanners/test_trivy_real_binary.py``).

Skipping ASH's output directory
-------------------------------
ASH's output directory, when it sits inside the target, is passed as
``--skip-dirs``. trivy reads that value as a comma-separated list of globs, so
glob characters are backslash-escaped and commas or quotes CSV-quoted (each form
checked on Linux with 0.69.3). Not verified on Windows, where the default output
directory name needs no escaping; ASH's suppression pass drops findings under the
output directory, apart from the converted work directory, whatever trivy does.

Exit codes
----------
trivy exits 0 whether or not it finds anything and 1 on any fatal error, so 0 is
the only success code. ASH passes ``--exit-code=0`` to make sure of the first:
``TRIVY_EXIT_CODE`` or an ``exit-code`` in the operator's trivy.yaml would
otherwise make trivy exit 1 on any finding, and the report would be refused
(``TrivyScannerBase._run_subprocess``). Each target (the source tree, then the
converted files) is judged by its own run's exit code; the base class would
otherwise carry the worst code from one target into the next (``scan``).
"""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    TrivyScannerBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.config_trust import (
    NOT_THE_OPERATORS,
    set_by_operator,
)
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    SarifReport,
)

#: trivy's severities that ASH reports as the same name. trivy's fifth, UNKNOWN,
#: is left to ASH's generic SARIF mapping.
TRIVY_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: The SARIF level trivy gives a result of each severity (``toSarifErrorLevel``).
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

#: Characters ``trivy --skip-dirs`` reads as glob syntax.
_GLOB_SPECIAL = frozenset("*?[]{}\\")

#: ``trivy --timeout`` when ASH's ``scan_timeout`` is null (unbounded). trivy has no
#: value that means "no deadline": measured with 0.75.0, ``trivy --timeout=0s`` is a deadline
#: that has already passed, and a scan that analyzes files one at a time (secret
#: scanning, OS packages) exits 1 with "context deadline exceeded". This is the largest
#: whole number of hours a Go duration holds, about 292 years; one hour more is refused
#: as an invalid duration.
UNBOUNDED_TRIVY_TIMEOUT = "2562047h"


def trivy_timeout(seconds: Optional[float]) -> str:
    """ASH's scan timeout in seconds, or None for unbounded, as trivy's ``--timeout``.

    Rounded up to a whole second and never below one, so a bound is never ``0s``.
    """
    if seconds is None:
        return UNBOUNDED_TRIVY_TIMEOUT
    return f"{max(1, math.ceil(seconds))}s"


def skip_dirs_value(path: str) -> str:
    """*path* as a ``--skip-dirs`` value trivy matches literally.

    trivy reads the value as a comma-separated list (CSV, so quotes group) of
    globs. Measured on 0.69.3: an unescaped ``a,b`` or ``x[1]`` left that directory
    scanned. Glob characters are backslash-escaped, then the value is CSV-quoted
    when it holds a comma, a quote or edge whitespace.
    """
    escaped = "".join("\\" + ch if ch in _GLOB_SPECIAL else ch for ch in path)
    if any(ch in escaped for ch in ',"') or escaped != escaped.strip():
        escaped = '"' + escaped.replace('"', '""') + '"'
    return escaped


class TrivyScannerConfigOptions(ScannerOptionsBase):
    scanners: Annotated[
        List[Literal["vuln", "misconfig", "secret", "license"]],
        Field(
            description=(
                "Which trivy scanners to run. Defaults to vuln only: ASH's default "
                "scanners already cover secrets (detect-secrets) and IaC "
                "misconfigurations (checkov, cfn-nag, cdk-nag), and license findings "
                "are a compliance question. Add secret, misconfig or license to run "
                "trivy's checks for them as well. Honored only when set by "
                "--config-overrides or a config file outside the scanned tree; set "
                "by a config in the tree, any set but the default is ignored with a "
                "warning."
            ),
            min_length=1,
        ),
    ] = ["vuln"]
    license_full: Annotated[
        bool,
        Field(
            description=(
                "Look for licenses in source file headers and license files too "
                "(trivy --license-full). Only used when scanners includes license."
            ),
        ),
    ] = False
    ignore_unfixed: Annotated[
        bool,
        Field(
            description=(
                "Report only vulnerabilities that have a fixed version (trivy "
                "--ignore-unfixed). Off by default: an unfixed vulnerability is still "
                "one, and turning this on withholds it from the report."
            ),
        ),
    ] = False
    disable_telemetry: Annotated[
        bool,
        Field(
            description="Disable sending anonymous usage data to Aqua",
        ),
    ] = True
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy config file (trivy.yaml), passed as trivy --config. Unset, "
                "ASH passes an empty one, so a trivy.yaml in the scanned repository is not "
                "read: its settings (severity, scan.skip-files, db.repository, ...) can "
                "drop findings with nothing in the report saying so, and module.dir "
                "can load WASM modules. Honored only when set by --config-overrides "
                "or a config file outside the scanned tree, for a file outside that "
                "tree; otherwise ignored with a warning. A relative path is taken "
                "from the directory of the config file that sets it, or from the "
                "working directory for --config-overrides, not from the source "
                "directory. A path that does not exist fails the scan."
            ),
        ),
    ] = None
    ignore_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy ignore file, passed as trivy --ignorefile. Honored only when set "
                "by --config-overrides or a config file outside the scanned tree, "
                "for a file outside that tree; a relative path is taken from the "
                "directory of the config file that sets it, or from the working "
                "directory for --config-overrides. Otherwise TRIVY_IGNOREFILE is "
                "used, for a file "
                "outside the tree, and failing that trivy gets an empty one, so a "
                ".trivyignore in the scanned repository does not remove findings. "
                "As for trivy-repo."
            ),
        ),
    ] = None
    secret_config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy secret scanning config (trivy-secret.yaml), passed as "
                "trivy --secret-config. Only read when scanners includes secret. Honored "
                "only under the same rule as ignore_file, and otherwise "
                "TRIVY_SECRET_CONFIG is used, for a file outside the tree, and "
                "failing that trivy gets an empty one, so a trivy-secret.yaml in the "
                "scanned repository does not disable secret rules. As for "
                "trivy-repo."
            ),
        ),
    ] = None
    offline: Annotated[
        bool,
        Field(
            description=(
                "Run in offline mode: skip database and check updates and use the "
                "vulnerability database already in trivy's cache. ASH still fails the "
                "scan when that database is past its 24h bound. When true, this "
                "scanner runs offline even if ASH does not. ASH's own offline mode "
                "(--offline or ASH_OFFLINE) applies whatever this is set to; false "
                "follows it."
            ),
        ),
    ] = False


class TrivyScannerConfig(ScannerPluginConfigBase):
    name: Literal["trivy"] = "trivy"
    enabled: bool = True
    options: Annotated[
        TrivyScannerConfigOptions,
        Field(description="Configure the trivy scanner"),
    ] = TrivyScannerConfigOptions()


@ash_scanner_plugin
class TrivyScanner(TrivyScannerBase[TrivyScannerConfig]):
    """Dependency vulnerability scanning with trivy."""

    #: Not Python-only: trivy is a native binary, installed from its pinned
    #: release asset, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    success_exit_codes: ClassVar[Set[int]] = {0}

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = TrivyScannerConfig()
        self.command = "trivy"
        self.subcommands = ["fs"]
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def _options(self) -> TrivyScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, TrivyScannerConfigOptions):
            return options
        return TrivyScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _reads_vulnerability_db(self) -> bool:
        return "vuln" in self._options().scanners

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before trivy runs whether it reads any file.

        ``trivy fs`` is handed the whole target and walks it itself. Which files
        it reads is decided by trivy's own analyzers: for ``vuln``, lockfiles and
        manifests in many formats, a list that changes between trivy releases,
        and with the operator's ``scanners`` including ``secret``,
        ``misconfig`` or ``license``, nearly any file. ASH makes no selection of
        its own that could come up empty, and trivy counts no targets, so a run
        with the tool never reports that it evaluated nothing either. None means
        "cannot tell", never "nothing to scan".
        """
        return None

    def _process_config_options(self) -> None:
        self._honor_scanner_set()
        self._append_trivy_options()
        if self._options().ignore_unfixed:
            self._plugin_log(
                "scanners.trivy.options.ignore_unfixed is true, which restricts which "
                "vulnerabilities reach the report: those with no fixed version are "
                "withheld, and the scan can pass with them present.",
                level=logging.WARNING,
            )
        return super()._process_config_options()

    def _honor_scanner_set(self) -> None:
        """Keep ``scanners`` only when the operator chose it; see the module docstring."""
        options = self._options()
        default = list(TrivyScannerConfigOptions.model_fields["scanners"].default)
        chosen = list(options.scanners)
        if chosen == default:
            return
        config = self.context.config if self.context is not None else None
        if set_by_operator(config, "scanners.trivy.options.scanners", chosen):
            return
        self._plugin_log(
            f"Ignoring scanners.trivy.options.scanners ({chosen}): {NOT_THE_OPERATORS}. "
            f"trivy runs the default set, {default}.",
            level=logging.WARNING,
        )
        if self.config is not None:
            self.config.options = options.model_copy(update={"scanners": default})

    def validate_plugin_dependencies(self) -> bool:
        """The binary, and offline, a vulnerability database for it to read.

        trivy refuses ``--skip-db-update`` when its cache holds no database ("cannot
        be specified on the first run"), so an offline scan without one is reported
        MISSING with the reason before trivy runs, rather than as a tool error.
        """
        if not super().validate_plugin_dependencies():
            return False
        if not (self._offline() and self._reads_vulnerability_db()):
            return True
        from automated_security_helper.utils.content_db_staleness import (
            _built_from_trivy,
        )

        try:
            _built_from_trivy(self.content_database_probe_context())
        except Exception as exc:  # noqa: BLE001 - every failure means "no usable database"
            self.dependency_unavailable_reason = (
                "trivy is in offline mode and has no vulnerability database to read "
                f"({exc}). Download one with network access (`trivy image "
                "--download-db-only`, with TRIVY_CACHE_DIR set to the cache this scan "
                "uses), or turn offline mode off."
            )
            self._plugin_log(self.dependency_unavailable_reason, level=logging.WARNING)
            return False
        return True

    def content_databases_in_use(self) -> List[Any]:
        """trivy's vulnerability database, when the ``vuln`` scanner ran."""
        if not self._reads_vulnerability_db():
            return []
        return super().content_databases_in_use()

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """The template scan, with each target judged by its own exit code.

        ScannerExecutor runs this one instance over the source and then the
        converted target, and the base class keeps the worst exit code across
        runs: a source run that failed (exit 1) made a clean converted run read
        as "trivy exited 1". Reset above every return of the template.
        """
        self.exit_code = 0
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv, results path and environment for one trivy run.

        ``global_ignore_paths`` is applied to every scanner's SARIF by ASH's
        suppression pass, so it is not translated into trivy flags.
        """
        if self.results_dir is None:
            raise ScannerError("TrivyScanner has no results directory")
        results_file = self.results_dir.joinpath(target_type, "results_sarif.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's: trivy
        # writes none when it fails, and the template reads whatever is here.
        results_file.unlink(missing_ok=True)

        final_args = self._resolve_arguments(target=target, results_file=results_file)
        # Each flag and its value as one token, so no path can be read as a flag.
        extra: List[str] = []
        # trivy's own deadline is 5 minutes and fails the scan when it passes.
        # Matched to ASH's, so the bound the operator set is the one that applies;
        # an unbounded ASH timeout is UNBOUNDED_TRIVY_TIMEOUT, since trivy reads 0s
        # as a deadline already passed.
        extra.append(f"--timeout={trivy_timeout(self._effective_scan_timeout())}")
        output_inside = self._output_dir_inside(target)
        if output_inside is not None:
            # ASH's own output under the target holds the converted copies of
            # archives and notebooks, which the converted target scans already.
            extra.append(f"--skip-dirs={skip_dirs_value(output_inside.as_posix())}")
        # trivy reads trivy.yaml and .trivyignore from its working directory, which
        # is the scanned repository. Either can drop findings with nothing in the
        # report saying so, so ASH passes its own unless the operator chose one.
        config_file, operators = self._trivy_file("config_file", "trivy-config.yaml")
        # Recorded for the staleness probe only when it is the operator's: ASH's
        # empty one is removed with the run, and trivy fails on a --config that
        # is missing (TrivyScannerBase._scan_config_file).
        self._scan_config_file = config_file if operators else None
        extra.append(f"--config={config_file}")
        # .trivyignore and trivy-secret.yaml as trivy-repo passes them
        # (TrivyScannerBase._trivy_input_file).
        extra.append(f"--ignorefile={self._ignore_file()}")
        extra.append(f"--secret-config={self._secret_config_file()}")
        # Before the target, which _resolve_arguments places after the options.
        target_index = final_args.index(Path(target).as_posix())
        final_args[target_index:target_index] = extra

        subprocess_env = (
            {**snapshot_environ(), **self.extra_env} if self.extra_env else None
        )
        return final_args, results_file, subprocess_env

    def _trivy_file(
        self, option: str, ash_name: str, ash_content: str = ""
    ) -> Tuple[str, bool]:
        """The trivy config file to pass, as an absolute POSIX path, and whether it is the operator's.

        The operator's (see ``_operator_path``), which must exist: a missing file
        would otherwise mean scanning without the rules the operator asked for.
        Otherwise an empty one ASH writes outside the scanned tree for this run
        (``empty_tool_config``), so nothing in the scanned repository is read as
        trivy configuration.
        """
        value = getattr(self._options(), option)
        # The path _operator_path checked, never one rebuilt from ``value``: the
        # check expands ``~``, so a rebuilt ``~/trivy.yaml`` was <source>/~/trivy.yaml.
        path = (
            self._operator_path(
                option,
                value,
                "A trivy.yaml can load WASM modules and drop findings, so trivy runs "
                "with ASH's empty config instead.",
            )
            if value
            else None
        )
        if path is not None:
            if not path.is_file():
                raise ScannerError(
                    f"scanners.trivy.options.{option} is {str(value)!r}, which is not "
                    f"a file (resolved to {path.as_posix()}). Fix the path or "
                    "unset the option; trivy is not run without it."
                )
            return path.as_posix(), True
        empty = empty_tool_config(ash_name, ash_content, context=self.context)
        return empty.resolve().as_posix(), False

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run trivy did not finish (any exit but 0)."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"trivy exited {self.exit_code}; run with --exit-code=0, it exits 0 "
                "whether or not it finds anything, so this run failed"
            )
        return super()._read_results_file(results_file)

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Tie each dependency result to one package copy and set trivy's severity."""
        sarif_report = self._attach_package_identity(sarif_report, target)
        for run in sarif_report.runs or []:
            rules = (
                (run.tool.driver.rules or []) if run.tool and run.tool.driver else []
            )
            by_id = {rule.id: rule for rule in rules}
            for result in run.results or []:
                severity = self._trivy_severity(result, rules, by_id)
                if severity is None:
                    continue
                if result.properties is None:
                    result.properties = PropertyBag()
                setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    @staticmethod
    def _trivy_severity(
        result: Any, rules: List[Any], by_id: Dict[str, Any]
    ) -> Optional[str]:
        """trivy's severity for *result*; see "Severity" above.

        The ``Severity:`` line of its message when it has one, else its rule's tag.
        """
        message = result.message.root.text if result.message else None
        for line in (message or "").splitlines():
            if line.startswith("Severity: "):
                own = line[len("Severity: ") :].strip()
                return own if own in TRIVY_SEVERITIES else None
        rule = None
        if result.ruleIndex is not None and 0 <= result.ruleIndex < len(rules):
            rule = rules[result.ruleIndex]
        if rule is None or (result.ruleId and rule.id != result.ruleId):
            rule = by_id.get(result.ruleId)
        if rule is None or rule.properties is None:
            return None
        tags = getattr(rule.properties, "tags", None) or []
        found = [tag for tag in tags if tag in TRIVY_SEVERITIES]
        # Exactly one, or no verdict: two severity tags would be a shape trivy
        # does not write, and guessing between them could under-rate a finding.
        if len(found) != 1:
            return None
        # The tag is the rating of the last result trivy wrote for the rule. A
        # result whose own level differs is rated otherwise, and is left to the
        # generic mapping rather than given another package's severity.
        level = getattr(result.level, "value", result.level)
        if level is not None and level != _SARIF_LEVEL[found[0]]:
            return None
        return found[0]
