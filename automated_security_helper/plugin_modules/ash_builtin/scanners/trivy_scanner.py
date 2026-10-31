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
operator: ``--config-overrides`` or a config file outside every git checkout and the
scanned directory (``utils/config_trust.set_by_operator``). Set from a config inside
a git checkout or the scanned directory, any set but the default is ignored with a warning, and trivy runs ``vuln``: a
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
  database refresh is the separate step above. trivy does not ask about new
  versions either: online every scan gets ``--skip-version-check``
  (``ONLINE_FLAGS``), and offline ``TRIVY_SKIP_VERSION_CHECK`` in its environment
  turns that check off (``utils/offline_tool_env.py``). The one exception is the
  ``misconfig`` scanner, off by default here: its Terraform checks download the
  module sources a ``.tf`` file names whatever flags are passed. Offline those
  checks are left out (``TrivyScannerBase._offline_misconfig_args``); online, with
  ``misconfig`` turned on, they run and can reach registry.terraform.io, git and
  the archive URLs the scanned repository's modules name.

* The operator's own ``TRIVY_*`` settings reach trivy (the sandbox passes every
  ``TRIVY_`` variable through). Those that drop results from the report with
  nothing in the run saying so (``TRIVY_SEVERITY``, ``TRIVY_IGNORE_UNFIXED`` and
  the others in ``OUTPUT_RESTRICTING_TRIVY_ENV``) are named in a warning, as the
  ``ignore_unfixed`` option is. ``TRIVY_SKIP_DIRS`` and ``TRIVY_SKIP_FILES``, and
  ``scan.skip-dirs`` / ``scan.skip-files`` in an honored config file, are given
  back to trivy as tokens of their own whenever ASH passes a skip flag itself:
  trivy reads a list flag from one source only, so ASH's flag would otherwise
  replace the operator's list rather than add to it.

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
passes ``--config``, ``--ignorefile`` and ``--secret-config`` pointing at files that
set nothing: the empty config ASH ships (``EMPTY_TOOL_CONFIG``) and an empty ignore
file and secret config ASH writes. ``config_file``, ``ignore_file`` and
``secret_config_file`` opt in to real ones, each honored only from the operator and
only for a file outside the scanned tree (``TrivyScannerBase._operator_path``): a
trivy.yaml can also load WASM modules (``module.dir``), and the other two drop
findings. Unset or refused, each falls back to the operator's environment for a file
outside the tree: ``TRIVY_CONFIG`` (``TrivyScannerBase._trivy_config_file``),
``TRIVY_IGNOREFILE`` and ``TRIVY_SECRET_CONFIG``
(``TrivyScannerBase._trivy_input_file``). ``trivy-repo`` passes the same three, and
its own ``--module-dir`` under the same rule. This scanner has no ``module_dir``
option, so trivy gets ``--module-dir`` naming an empty directory ASH makes outside
the tree for the run, and loads no WASM module from ``~/.trivy/modules`` or a
config's ``module.dir``. The database update runs from outside the tree with an
explicit ``--config`` (``TrivyScannerBase._shared_update_flags``). With those, trivy
0.75.0 reads nothing else from a default location: ``--ignore-policy`` (a Rego file) has none, and an ignore policy
named by the tree's ``trivy.yaml`` does not apply because that file is not read
(``tests/integration/scanners/test_trivy_real_binary.py``).

Skipping ASH's output directories
---------------------------------
The directories ASH writes its own output to, when they sit inside the target, are
passed as ``--skip-dirs``: the ones ``ScannerPluginBase._ash_output_dirs_inside``
names, as every scanner that hands its tool a directory takes them. They are this
run's output directory and the default ``.ash/ash_output`` an earlier run can have
left in the tree, each whole while git lists no committed file in it. The default
output directory is a fixed path inside the scanned tree, and a repository can
commit files to it. For one that does, only ASH's own directories in it are
skipped (``analysis``, ``reports``, ``scanners``, ``converted`` and where an MCP
scan sets earlier results aside), each that holds no committed file, so a file the
repository committed there is scanned. The files ASH writes at the root of such a
directory reach trivy, and ASH's drop of results located in its output directories
removes the ones trivy reports in them, keeping the committed files' results
(``scan_output_dirs.drop_results_in_ash_output_dirs``). This scanner used to pass
the output directory as one path, which left a committed file in it unscanned.

When that helper cannot name the directories (it returns none if naming them raises
an OSError, TypeError or ValueError, as with a working directory that was deleted),
and this run's output directory is inside the target, trivy is told to skip that
directory whole, with a warning. The drop after the scan names the same
directories and drops nothing when naming them raises, so it cannot be left to
filter what trivy then reads.

trivy reads each value as a comma-separated list of globs, so glob characters are
backslash-escaped and commas or quotes CSV-quoted (each form checked on Linux with
0.69.3). Not verified on Windows, where the default output directory name needs no
escaping; ASH's suppression pass drops findings under the output directory, apart
from the converted work directory, whatever trivy does.

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
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.config.tool_config_trust import empty_tool_directory
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (  # noqa: F401 -- TRIVY_SEVERITIES, _SARIF_LEVEL, UNBOUNDED_TRIVY_TIMEOUT and trivy_timeout are kept importable from here
    _SARIF_LEVEL,
    TRIVY_SEVERITIES,
    UNBOUNDED_TRIVY_TIMEOUT,
    TrivyScannerBase,
    skip_dirs_value,
    trivy_timeout,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.config_trust import (
    NOT_THE_OPERATORS,
    refusal_warning,
    set_by_operator,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.schemas.sarif_schema_model import SarifReport

# UNBOUNDED_TRIVY_TIMEOUT and trivy_timeout live in the shared base since trivy-repo
# passes the same bound; both names stay importable from this module.


class TrivyScannerConfigOptions(ScannerOptionsBase):
    scanners: Annotated[
        List[Literal["vuln", "misconfig", "secret", "license"]],
        Field(
            description=(
                "Which trivy scanners to run. Defaults to vuln only: ASH's default "
                "scanners already cover secrets (detect-secrets) and IaC "
                "misconfigurations (checkov, cfn-nag, cdk-nag), and license findings "
                "are a compliance question. Add secret, misconfig or license to run "
                f"trivy's checks for them as well. {SET_BY_THE_OPERATOR} Set by such "
                "a config, any set but the default is ignored with a warning."
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
            description=(
                "Disable sending anonymous usage data to Aqua (--disable-telemetry). "
                "Only the operator sets it to false, with --config-overrides or in a "
                "config file outside every git checkout and the scanned directory: a "
                "config file inside one, or one an MCP client delivered, may set it "
                "to true but not to false. Offline, trivy sends none whatever this "
                "says. As for trivy-repo."
            ),
        ),
    ] = True
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy config file (trivy.yaml), passed as --config. "
                f"{SET_BY_THE_OPERATOR} The file is used only when it is outside the "
                "scanned tree; otherwise it is ignored with a warning. A relative "
                "path is taken from the directory of the config "
                "file that sets it, or from the working directory for "
                "--config-overrides, not from the source directory. Unset or "
                "ignored, ASH passes TRIVY_CONFIG when that names a file outside the "
                "scanned tree (a relative path in it is taken from the working "
                "directory), and otherwise an empty config of its own, so a "
                "trivy.yaml in the scanned repository is not read: its settings "
                "(severity, scan.skip-files, db.repository, ...) can drop findings "
                "with nothing in the report saying so, and module.dir can load WASM "
                "modules. A path that does not exist fails the scan."
            ),
        ),
    ] = None
    ignore_file: Annotated[
        Path | str | None,
        Field(
            description=(
                f"A trivy ignore file, passed as --ignorefile. {SET_BY_THE_OPERATOR} "
                "The file is used only when it is outside the scanned tree; a "
                "relative path is taken from the directory of the config file that "
                "sets it, or from the working directory for --config-overrides and "
                "the environment variable. Unset, TRIVY_IGNOREFILE is used the same "
                "way, and otherwise trivy gets an empty one, so a .trivyignore in the "
                "scanned repository does not remove findings. As for trivy-repo."
            ),
        ),
    ] = None
    secret_config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy secret scanning config (trivy-secret.yaml), passed as "
                "--secret-config. Only read when scanners includes secret. "
                f"{SET_BY_THE_OPERATOR} The file is used only when it is outside the "
                "scanned tree, and a relative path is taken as for ignore_file. "
                "Unset, TRIVY_SECRET_CONFIG is used the same way, and otherwise trivy "
                "gets an empty one, so a trivy-secret.yaml in the scanned repository "
                "does not disable secret rules. As for trivy-repo."
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
            refusal_warning(
                f"Ignoring scanners.trivy.options.scanners ({chosen}): "
                f"{NOT_THE_OPERATORS}. trivy runs the default set, {default}.",
                NOT_THE_OPERATORS,
            ),
            level=logging.WARNING,
        )
        if self.config is not None:
            self.config.options = options.model_copy(update={"scanners": default})

    # validate_plugin_dependencies is TrivyScannerBase's: the binary, and offline a
    # vulnerability database for the scan to read, shared with trivy-repo.

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

        ``global_ignore_paths`` reaches trivy as trivy-repo's do: ``--skip-files``
        and ``--skip-dirs`` for the ignored paths trivy's option can carry
        (``TrivyScannerBase._link_skip_args``). ASH's suppression pass still drops
        the findings of any it cannot.
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
        # ASH's own output directories inside the target, each as its own
        # --skip-dirs: the converted copies of archives and notebooks (which the
        # converted target scans already) and reports and scanner results. One
        # helper builds the tokens for this scanner and trivy-repo
        # (TrivyScannerBase._output_dir_skip_args), so the two cannot drift apart.
        extra.extend(self._output_dir_skip_args(target, target_type))
        # trivy reads trivy.yaml and .trivyignore from its working directory, which
        # is the scanned repository. Either can drop findings with nothing in the
        # report saying so, so ASH passes its own unless the operator chose one
        # (TrivyScannerBase._trivy_config_file, as trivy-repo does).
        config_token = f"--config={self._trivy_config_file()}"
        extra.append(config_token)
        # trivy loads the WASM modules in --module-dir (default ~/.trivy/modules,
        # or a trivy.yaml's module.dir). This scanner has no module_dir option, so
        # it always gets an empty directory, as trivy-repo does when its option is
        # unset.
        modules = empty_tool_directory("trivy-modules", context=self.context)
        extra.append(f"--module-dir={modules.as_posix()}")
        # .trivyignore and trivy-secret.yaml as trivy-repo passes them
        # (TrivyScannerBase._trivy_input_file). The secret config is read only by
        # the secret scanner, so a missing operator file fails only a scan that
        # runs it; the scanner set is read from the --config token just added.
        extra.append(f"--ignorefile={self._ignore_file()}")
        extra.append(f"--secret-config={self._secret_config_file([config_token])}")
        # Each link leaving the target, and each path the global ignore paths ignore.
        # The operator's own skip entries are sized first and kept out of this share
        # of the argument budget (TrivyScannerBase._operator_skip_plan): ASH's
        # tokens have a fallback when left out, the operator's have none.
        operator_skips = self._operator_skip_plan(extra)
        extra.extend(
            self._link_skip_args(
                target, global_ignore_paths, reserved=operator_skips.reserved
            )
        )
        # The operator's own skip lists, which ASH's skip flags would otherwise
        # replace (TrivyScannerBase._operator_skip_args).
        extra.extend(self._operator_skip_args(extra, operator_skips))
        # Before the target, which _resolve_arguments places LAST (after the
        # options): the last token equal to the target's spelling, not the first,
        # so a relative target spelled like an earlier value ("sarif", "vuln",
        # "trivy") does not move the insertion point into the options.
        target_token = Path(target).as_posix()
        target_index = len(final_args) - 1 - final_args[::-1].index(target_token)
        final_args[target_index:target_index] = extra
        if self._offline():
            # Only with misconfig, which the operator has to add: trivy's Terraform
            # checks download module sources (TrivyScannerBase._offline_misconfig_args).
            final_args = self._offline_misconfig_args(final_args)

        subprocess_env = (
            {**snapshot_environ(), **self.extra_env} if self.extra_env else None
        )
        return final_args, results_file, subprocess_env

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
        """Tie each dependency result to one package copy and set trivy's severity.

        The severity step is ``TrivyScannerBase._attach_trivy_severity``, shared
        with trivy-repo; see "Severity" above for the rule.
        """
        sarif_report = self._attach_package_identity(sarif_report, target)
        return self._attach_trivy_severity(sarif_report)
