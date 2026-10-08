# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ``trivy`` scanner: ``trivy fs``, vulnerabilities by default, beside ``trivy-repo``.

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

Any of the four can be turned on with ``scanners.trivy.options.scanners``.

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

* Online, trivy applies its own rule: a database past its ``NextUpdate`` is
  replaced before the scan, and the scan fails if the download does. ASH passes
  nothing to change that, because trivy has no max-age control to pass; the
  registry's bound IS trivy's rule, so the post-scan check agrees with it.
* Offline, ASH passes ``--skip-db-update`` (with ``--skip-java-db-update``,
  ``--offline-scan`` and ``--skip-check-update``), which makes trivy use any
  database it has. The post-scan check is what holds that database to the bound.
  With no database at all trivy cannot scan offline, so the scanner reports
  MISSING with the reason before trivy runs.

The database is only read by ``vuln``. With ``vuln`` turned off nothing is
measured and the offline database check is skipped.

Severity
--------
Each result's ASH severity is trivy's own severity for it (CRITICAL, HIGH, MEDIUM,
LOW), read from the severity tag trivy writes on the result's rule. It is the
value trivy's ``--severity`` filter uses, which is how ASH's
``severity_threshold`` is passed to trivy, so the threshold and the reported
severity cannot disagree. Without this, ASH would bucket the rule's
``security-severity`` (a CVSS base score), and a finding trivy rates HIGH with a
6.5 CVSS score would pass trivy's HIGH filter and be reported MEDIUM. A result
whose severity is UNKNOWN keeps ASH's generic SARIF mapping (the CVSS score, then
the SARIF level).

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
``secret_config_file`` opt in to real ones. ``config_file`` is honored only from the
operator and only for a file outside the scanned tree, because a trivy.yaml can load
WASM modules (``module.dir``); see ``_operator_config_file``. ``trivy-repo`` is
unchanged and still reads them.

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
trivy exits 0 whether or not it finds anything (ASH does not pass
``--exit-code``) and 1 on any fatal error, so 0 is the only success code.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugin_modules.ash_trivy_plugins._trivy_scanner_base import (
    TrivyScannerBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.config_trust import (
    inside_scanned_tree,
    set_by_operator,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    SarifReport,
)

#: trivy's severities that ASH reports as the same name. trivy's fifth, UNKNOWN,
#: is left to ASH's generic SARIF mapping.
TRIVY_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: Characters trivy's ``--skip-dirs`` reads as glob syntax.
_GLOB_SPECIAL = frozenset("*?[]{}\\")


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
                "trivy's checks for them as well."
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
                "A trivy config file (trivy.yaml), passed as --config. Unset, ASH "
                "passes an empty one, so a trivy.yaml in the scanned repository is not "
                "read: its settings (severity, scan.skip-files, db.repository, ...) can "
                "drop findings with nothing in the report saying so, and module.dir "
                "can load WASM modules. Honored only when set by --config-overrides "
                "or a config file outside the scanned tree, for a file outside that "
                "tree; otherwise ignored with a warning. A path "
                "that does not exist fails the scan."
            ),
        ),
    ] = None
    ignore_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy ignore file (.trivyignore or .trivyignore.yaml), relative to "
                "the source directory, passed as --ignorefile. Unset, ASH passes an "
                "empty one, so a .trivyignore in the scanned repository does not hide "
                "findings; use ASH suppressions, which are reported. A path that does "
                "not exist fails the scan."
            ),
        ),
    ] = None
    secret_config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "A trivy secret-scanning config (trivy-secret.yaml), relative to the "
                "source directory, passed as --secret-config. Only read when scanners "
                "includes secret. Unset, ASH passes its own empty one, so a "
                "trivy-secret.yaml in the scanned repository cannot disable rules. A "
                "path that does not exist fails the scan."
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
    # Off by default, unlike the other scanners of community modules: this module
    # already held trivy-repo, and every config that lists it for trivy-repo would
    # otherwise start running trivy a second time, on a database download, with
    # findings it never asked for. `scanners.trivy.enabled: true` turns it on.
    enabled: bool = False
    options: Annotated[
        TrivyScannerConfigOptions,
        Field(description="Configure the trivy scanner"),
    ] = TrivyScannerConfigOptions()


@ash_scanner_plugin
class TrivyScanner(TrivyScannerBase[TrivyScannerConfig]):
    """Dependency vulnerability scanning with trivy."""

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

    def _process_config_options(self) -> None:
        self._append_trivy_options()
        if self._options().ignore_unfixed:
            self._plugin_log(
                "scanners.trivy.options.ignore_unfixed is true, which restricts which "
                "vulnerabilities reach the report: those with no fixed version are "
                "withheld, and the scan can pass with them present.",
                level=logging.WARNING,
            )
        return super()._process_config_options()

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
        timeout = self._effective_scan_timeout()
        # trivy's own deadline is 5 minutes and fails the scan when it passes.
        # Matched to ASH's, so the bound the operator set is the one that applies;
        # an unbounded ASH timeout is trivy's 0s, which trivy reads as no deadline.
        extra.append(f"--timeout={int(timeout) if timeout is not None else 0}s")
        output_inside = self._output_dir_inside(target)
        if output_inside is not None:
            # ASH's own output under the target holds the converted copies of
            # archives and notebooks, which the converted target scans already.
            extra.append(f"--skip-dirs={skip_dirs_value(output_inside.as_posix())}")
        # trivy reads trivy.yaml and .trivyignore from its working directory, which
        # is the scanned repository. Either can drop findings with nothing in the
        # report saying so, so ASH passes its own unless the operator chose one.
        extra.append(f"--config={self._trivy_file('config_file', 'trivy-config.yaml')}")
        extra.append(
            f"--ignorefile={self._trivy_file('ignore_file', 'trivyignore.txt')}"
        )
        # trivy-secret.yaml in the working directory can disable secret rules. An
        # empty file is a decode error in trivy, so ASH's holds an empty mapping.
        extra.append(
            "--secret-config="
            + self._trivy_file("secret_config_file", "trivy-secret.yaml", "{}\n")
        )
        # Before the target, which _resolve_arguments places after the options.
        target_index = final_args.index(Path(target).as_posix())
        final_args[target_index:target_index] = extra

        subprocess_env = (
            {**snapshot_environ(), **self.extra_env} if self.extra_env else None
        )
        return final_args, results_file, subprocess_env

    def _trivy_file(self, option: str, ash_name: str, ash_content: str = "") -> str:
        """The trivy config or ignore file to pass, as an absolute POSIX path.

        The configured one, a relative path anchored on the source directory, which
        must exist: a missing file would otherwise mean scanning without the rules
        the operator asked for. Unset, an empty one ASH writes next to its results,
        so nothing in the scanned repository is read as trivy configuration.
        """
        value = getattr(self._options(), option)
        if value and option == "config_file" and not self._operator_config_file(value):
            value = None
        if value:
            candidate = Path(value)
            if not candidate.is_absolute():
                if self.context is None:
                    raise ScannerError("TrivyScanner has no plugin context")
                candidate = Path(self.context.source_dir) / candidate
            if not candidate.is_file():
                raise ScannerError(
                    f"scanners.trivy.options.{option} is {str(value)!r}, which is not "
                    f"a file (resolved to {candidate.as_posix()}). Fix the path or "
                    "unset the option; trivy is not run without it."
                )
            return candidate.resolve().as_posix()
        if self.results_dir is None:
            raise ScannerError("TrivyScanner has no results directory")
        empty = self.results_dir.joinpath(ash_name)
        empty.parent.mkdir(parents=True, exist_ok=True)
        with open_for_write(empty) as handle:
            handle.write(ash_content)
        return empty.resolve().as_posix()

    def _operator_config_file(self, value: Path | str) -> bool:
        """Whether ``config_file`` may be handed to trivy; logs why when not.

        A trivy.yaml is more than filters: ``module.dir`` and
        ``module.enable-modules`` make trivy load and run WASM modules from a
        directory it names. So a config file is used only when the operator set
        the option (``--config-overrides`` or a config file outside the scanned
        tree, see ``utils/config_trust.py``) and it resolves outside that tree.
        ``ignore_file`` and ``secret_config_file`` hold patterns, not
        code, and are not gated.
        """
        if self.context is None:
            raise ScannerError("TrivyScanner has no plugin context")
        source_dir = Path(self.context.source_dir)
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = source_dir / candidate
        if not set_by_operator(
            self.context.config, "scanners.trivy.options.config_file", value
        ):
            reason = (
                "it came from a config file in the scanned tree; set it with "
                "--config-overrides or a config file outside the tree"
            )
        elif inside_scanned_tree(candidate, source_dir):
            reason = "it is inside the scanned tree"
        else:
            return True
        self._plugin_log(
            f"Ignoring scanners.trivy.options.config_file ({str(value)!r}): {reason}. "
            "A trivy.yaml can load WASM modules, so trivy runs with ASH's empty "
            "config instead.",
            level=logging.WARNING,
        )
        return False

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run trivy did not finish (any exit but 0)."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"trivy exited {self.exit_code}; it exits 0 whether or not it finds "
                "anything, so this run failed"
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
        """trivy's severity for *result*, from its rule's tags; see "Severity" above."""
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
        return found[0] if len(found) == 1 else None
