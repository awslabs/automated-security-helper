"""Module containing the Checkov security scanner implementation."""

import logging
import os
import platform
from pathlib import Path
from typing import Annotated, ClassVar, List, Literal

from pydantic import Field, model_validator
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.constants import ASH_ASSETS_DIR
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolArgs,
    ToolExtraArg,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    PropertyBag,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.cfn_template_model import (
    CloudFormationTemplateModelError,
    get_model_from_template,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.download_utils import current_bin_path
from automated_security_helper.utils.normalizers import get_normalized_filename
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import CFN_NAG_GEM_VERSION


class CfnNagScannerConfigOptions(ScannerOptionsBase):
    pass


class CfnNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cfn-nag"] = "cfn-nag"
    enabled: bool = True
    options: Annotated[
        CfnNagScannerConfigOptions,
        Field(description="Configure CFN Nag scanner"),
    ] = CfnNagScannerConfigOptions()


@ash_scanner_plugin
class CfnNagScanner(ScannerPluginBase[CfnNagScannerConfig]):
    """CfnNagScanner implements SECRET scanning using CFN Nag."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        if self.config is None:
            self.config = CfnNagScannerConfig()
        self.command = "cfn_nag_scan"
        self.tool_type = ScannerToolType.IAC
        self.rule_directory = ASH_ASSETS_DIR.joinpath("appsec_cfn_rules")
        extra_args = [
            ToolExtraArg(
                key="--print-suppression",
                value=None,
            ),
            # --isolate-custom-rule-exceptions bounds the damage a defect in one of the
            # four rules under --rule-directory can do. cfn_nag's CustomRuleLoader wraps
            # each rule in `rescue ScriptError, StandardError` and then immediately
            # re-raises unless this flag is set; the exception matches none of the
            # rescue clauses in CfnNag#audit and the executor has none at all, so it
            # reaches the top of the process, which exits before rendering any output.
            # The cost is therefore not the broken rule's verdict but every rule's
            # verdict on that template. That is not hypothetical: two of the four rules
            # in this directory shipped a call that raised ArgumentError on every
            # invocation, and the measurements for it are in the docstrings of
            # tests/integration/scanners/test_cfn_nag_custom_rules.py, which is also
            # where the argv that reproduces both failure modes lives.
            #
            # This changes cfn_nag's failure mode for every rule it loads, not only for
            # the ones ASH ships, which is the intended trade: a rule that raises should
            # cost its own verdict and nothing else.
            ToolExtraArg(
                key="--isolate-custom-rule-exceptions",
                value=None,
            ),
            # --ignore-fatal is deliberately absent, and its absence is load-bearing.
            #
            # cfn-model raises when it cannot parse a template -- an unresolved Ref or
            # GetAtt to a logical id not declared in that file is the common case -- and
            # cfn_nag turns that into a violation with id FATAL. A FATAL violation
            # carries no logical resource ids, and the SARIF renderer emits one result
            # per id, so FATAL renders as nothing whether or not this flag is passed.
            # What the flag additionally does is prune FATAL before the failure count is
            # computed, which drops the process exit status to 0.
            #
            # That leaves a template no rule was ever evaluated against reporting a
            # complete SARIF document, a fully populated rule driver, zero results, zero
            # bytes of stderr, and exit 0 -- identical in every observable respect to a
            # compliant template. Measured against cfn-nag 0.8.10 and cfn-model 0.6.6 --
            # the versions assets/Gemfile.lock pins and CFN_NAG_GEM_VERSION installs --
            # over four template shapes with
            #
            #   cfn_nag_scan --print-suppression [--ignore-fatal] \
            #       --output-format sarif --input-path <template>
            #
            # an unresolved-Ref template and a clean template both give exit 0 with zero
            # results when the flag is passed, and the two SARIF documents are the same
            # size. Without the flag the unresolved-Ref template gives exit 1 with zero
            # results while the clean template gives exit 0, and a template with real
            # findings gives a non-zero exit with a non-empty result set. So the pair
            # (exit status, result count) separates all three, and _evaluated_no_rule
            # below reads it. A suppressed violation is removed before the count, so a
            # fully suppressed template still exits 0 and is not mistaken for a failure.
            ToolExtraArg(
                key="--rule-directory",
                value=self.rule_directory.as_posix(),
            ),
        ]
        if ASH_LOGGER.level == logging.DEBUG:
            extra_args.append(
                ToolExtraArg(
                    key="--verbose",
                    value=None,
                )
            )
        self.args = ToolArgs(
            format_arg="--output-format",
            format_arg_value="sarif",
            scan_path_arg="--input-path",
            extra_args=extra_args,
        )

        super().model_post_init(context)

    @staticmethod
    def _missing_gem_prerequisites() -> List[str]:
        """Prerequisites for installing cfn-nag that are absent from this machine.

        Two of them, and neither is speculative.

        RubyGems, because cfn-nag is a gem. And a C compiler, because its closure
        does not install without one: cfn-nag depends on cfn-model, which requires
        ``psych ~> 3``, and psych has a C extension over libyaml. No psych 3.x release
        publishes a precompiled gem for a modern Windows ABI -- checked against the
        RubyGems API, 3.1.0 is the newest 3.x carrying any Windows binary and it is
        tagged x64-mingw32 while Ruby 3.1+ needs x64-mingw-ucrt -- so it must build
        from source. ASH's own container installs build-essential purely to get
        through this step and then purges it.

        Measured, not assumed: on windows-latest the gem install reached
        "ERROR: Failed to build gem native extension" and returned 1, which failed
        `ash dependencies install` outright and took every other scanner's install
        down with it. Checking first turns that into cfn-nag reporting itself as
        unprovisionable on this platform -- named in the installer's output, next to
        npm-audit -- which is a constraint rather than a malfunction.

        The two platforms are probed differently because the requirement differs.
        On POSIX, `cc`/`gcc`/`clang` on PATH is the requirement, and the hosted Linux
        and macOS runners have it, which is why cfn-nag installs and runs there.

        Windows is probed on RI_DEVKIT instead, because on Windows a compiler being
        present does not predict the build succeeding. Measured on 18e5cba9: extconf
        found psych's vendored libyaml and wrote a Makefile ("checking for yaml.h...
        yes", "creating Makefile"), and make then failed with

            No rule to make target
            '/C/hostedtoolcache/windows/Ruby/3.3.12/x64/include/ruby-3.3.0/ruby.h'

        -- an MSYS-translated path handed to a make from a different tree. What the
        build needs is one coherent MSYS2 environment where sh, make and gcc all come
        from the same install, and RI_DEVKIT is the marker for that: `ridk enable`
        sets it (rubyinstaller2, lib/ruby_installer/build/msys2_installation.rb) as
        part of activating that environment. Probing for a compiler instead is worse
        than not probing, because it passes on a stray gcc and licenses the attempt.

        The CI leg supplies that environment with `ruby/setup-ruby`, whose default
        `windows-toolchain` unpacks the ucrt64 gcc bundle and runs `ridk enable`; see
        .github/actions/run-scan-test/action.yml. A Windows machine without it still
        reports cfn-nag as unprovisionable rather than failing every other scanner's
        install, which is the intended behavior and not a platform exclusion.
        """
        missing: List[str] = []
        if find_executable("gem") is None:
            missing.append("RubyGems (`gem`) is not on PATH")

        if platform.system() == "Windows":
            # Windows is checked on RI_DEVKIT rather than on a compiler being present,
            # and the difference is not pedantic. A first attempt probed for
            # cc/gcc/clang; windows-latest has a gcc on PATH (MinGW arrives with other
            # tooling in that image), so the probe passed, the gem install ran, and it
            # still died with "Failed to build gem native extension" -- because Ruby's
            # mkmf needs a toolchain matching its own ABI, x64-mingw-ucrt, not whatever
            # gcc happens to be reachable. RI_DEVKIT is the variable RubyInstaller's
            # devkit and ruby/setup-ruby both export, so it is the marker that actually
            # tracks buildability here.
            if not os.environ.get("RI_DEVKIT"):
                missing.append(
                    "no Ruby DevKit (RI_DEVKIT is unset), and cfn-nag's `psych` "
                    "dependency publishes no precompiled gem for this Ruby ABI, so it "
                    "has to build from source"
                )
        elif not any(find_executable(cc) for cc in ("cc", "gcc", "clang")):
            missing.append(
                "no C compiler (cc, gcc or clang) is on PATH, and cfn-nag's `psych` "
                "dependency has to build from source"
            )
        return missing

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "CfnNagScanner":
        """Set up the installation command for cfn-nag.

        cfn-nag is a Ruby gem, not a release binary, so it does not go through the
        pinned-digest download path the way grype, syft and trivy do. Forcing it
        into that path would mean pinning a digest for every gem in its dependency
        closure, which is what a lockfile is for.

        What that costs, stated plainly: this command pins cfn-nag itself exactly
        and lets RubyGems resolve the closure within cfn-nag's own constraints.
        The committed ``assets/Gemfile.lock`` pins the whole closure and remains
        the stricter artifact -- it is what the container image builds against.
        ``bundle install --gemfile`` was tried instead and rejected: that lock's
        PLATFORMS section lists only ``ruby``, so on Windows and macOS bundler
        needs the platform added before it will resolve, and an installer that
        works on one platform and errors on two is worse than one that pins
        slightly less.

        A Ruby interpreter is a prerequisite, not something ASH installs, and the
        command is therefore declared only when `gem` is actually present.

        Declaring it unconditionally was wrong in a way worth recording. `gem`
        missing makes run_command return 1 on FileNotFoundError, which counts as a
        failed install command, which fails the whole run -- so on a machine without
        Ruby, `ash dependencies install` would exit non-zero for every plugin
        together, before any scan. That is a different and worse outcome than
        cfn-nag being unavailable, and it contradicts how the same condition is
        treated one plugin over: npm-audit needs a Node runtime ASH does not
        install, declares no command, and is reported as a constraint rather than a
        malfunction. Two identical situations should not diverge on the accident of
        whether one of them declares a command that cannot work.

        With the gate, a machine without Ruby reports cfn-nag under "no install path
        on this platform" -- by name, next to npm-audit -- and a machine with Ruby
        installs it.
        """
        missing = self._missing_gem_prerequisites()
        if missing:
            ASH_LOGGER.warning(
                f"cfn-nag cannot be installed here: {', '.join(missing)}. It will be "
                "reported as having no install path on this machine rather than "
                "failing the install of every other scanner."
            )
            return self

        # --user-install and --bindir together, and both are load-bearing.
        #
        # --user-install because a plain `gem install` writes to the interpreter's
        # GEM_HOME, which on a stock Linux runner is root-owned; without it the
        # install needs sudo and fails without it.
        #
        # --bindir because the binstub otherwise lands in whichever bin directory
        # that Ruby installation happens to use, and ASH looks on PATH and in
        # ASH_BIN_PATH -- not in a user gem bin. Pointing it at ASH_BIN_PATH makes
        # cfn-nag findable without depending on how the host arranges its Ruby.
        # Verified that a relocated binstub still activates the gem from the user
        # directory, since Gem.path includes it by default.
        command = CustomCommand(
            args=[
                "gem",
                "install",
                "cfn-nag",
                "-v",
                CFN_NAG_GEM_VERSION,
                "--no-document",
                "--user-install",
                "--bindir",
                str(current_bin_path()),
            ],
            shell=False,
        )
        for target_platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                    command
                ]
        return self

    def _process_config_options(self):
        # Add any additional config option parsing here, if necessary
        # For Python-based scanners, this typically won't be needed as we will access
        # the configuration directly from the self.config object.
        return super()._process_config_options()

    @staticmethod
    def _evaluated_no_rule(file_sarif: SarifReport, returncode) -> bool:
        """Whether this per-file run failed without rendering a single result.

        cfn_nag's exit status is its count of failing violations, and every violation a
        rule produces carries at least one logical resource id -- ``BaseRule#audit``
        returns nil when the id list is empty, so a rule cannot report a violation
        against nothing. The SARIF renderer emits one result per id. Put together, a
        rule violation always renders at least one SARIF result.

        The one failing violation that renders nothing is FATAL, which cfn_nag
        manufactures when cfn-model raises during parsing and which has no ids at all.
        So a non-zero exit with an empty result set means the count came from something
        SARIF could not represent, and the only thing in that category is a template
        that was never evaluated. That is why this reads the exit status rather than
        re-running the template: with ``--ignore-fatal`` withheld the signal is already
        on the first invocation, so no second invocation is needed.

        Deliberately not gated on the rule driver being populated. An empty driver
        alongside a non-zero exit is a stronger reason to distrust the run, not a
        reason to exempt it.
        """
        if returncode is None:
            return False
        try:
            code = int(returncode)
        except (TypeError, ValueError):
            # An exit status ASH cannot read is not evidence that rules ran.
            return True
        if code == 0:
            return False
        return not any(run.results for run in (file_sarif.runs or []))

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — CfnNag overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CfnNagScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Execute CFN Nag scan and return results.

        Args:
            target: Path to scan

        Returns:
            SarifReport containing the scan findings and metadata

        Raises:
            ScannerError: If the scan fails or results cannot be parsed
        """
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Top of the method, above all five early returns, for the reason the same pair
        # carries in cdk_nag_scanner: an initialization placed further down is inherited by
        # whichever return sits above it, and the executor then reads stale attributes from
        # the previous target.
        self.targets_attempted = 0
        self.targets_failed = 0

        tool_component = ToolComponent(
            name="cfn_nag",
            semanticVersion=self.tool_version,
            version=self.tool_version,
            informationUri="https://github.com/stelligent/cfn_nag",
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine=self.command,
                            executionSuccessful=True,
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=target)
                            ),
                        )
                    ],
                )
            ],
        )
        # Check if the target directory is empty or doesn't exist
        if not target.exists() or not any(target.iterdir()):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return sarif_report

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        try:
            target_results_dir = self.results_dir.joinpath(target_type)

            orig_scannable = (
                list(self.context.work_dir.glob("**/*.*"))
                if target_type == "converted"
                else scan_set(
                    source=self.context.source_dir,
                    output=self.context.output_dir,
                    # filter_pattern=r"\.(yaml|yml|json)$",
                )
            )
            ASH_LOGGER.debug(
                f"Found {len(orig_scannable)} files in scan set. Checking for possible CloudFormation templates"
            )

            scannable = []
            for f in orig_scannable:
                pf = Path(f)
                if (
                    pf.name.endswith(".json")
                    or pf.name.endswith(".yaml")
                    or pf.name.endswith(".yml")
                ):
                    scannable.append(pf.as_posix())
            joined_files = "\n- ".join(scannable)
            ASH_LOGGER.debug(
                f"Found {len(scannable)} JSON/YAML files:\n- {joined_files}"
            )

            if len(scannable) == 0:
                self._plugin_log(
                    f"No JSON/YAML files found in {target_type} directory to scan. Exiting.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(
                    target=target,
                    target_type=target_type,
                )
                return sarif_report

            # Process each template file. The counters above replace a local failed_files
            # list that was appended to on both failure paths and never read, so a run that
            # failed on every template still produced an empty-but-successful report.
            sarif_tool = Tool(driver=tool_component)
            sarif_output_file = target_results_dir.joinpath("cfn_nag.sarif")
            sarif_output_file.parent.mkdir(exist_ok=True, parents=True)
            # Templates for which cfn_nag_scan wrote nothing at all. Collected rather
            # than raised on immediately so that every template is still attempted and
            # named, and the partial report still reaches disk; the raise happens once,
            # below, after the report is written.
            unrendered: List[str] = []
            for cfn_file in scannable:
                try:
                    self._plugin_log(
                        f"Checking if file is CloudFormation: {cfn_file}",
                        target_type=target_type,
                        level=logging.DEBUG,
                    )
                    cfn_model = get_model_from_template(template_path=Path(cfn_file))
                    if cfn_model:
                        self._plugin_log(
                            f"File *is* CloudFormation: {cfn_file}",
                            target_type=target_type,
                            level=logging.DEBUG,
                        )
                    else:
                        self._plugin_log(
                            f"cfn_model is falsey, but no error was thrown: {cfn_file}",
                            target_type=target_type,
                            level=logging.DEBUG,
                        )
                except CloudFormationTemplateModelError as e:
                    # A document carrying a Resources mapping is CloudFormation, so
                    # failing to model it is an ASH-side limitation rather than a
                    # property of the file. Counted as a failed target, which is the
                    # whole point of splitting this out of the skip below: the skip sits
                    # above `targets_attempted += 1`, so a scan set in which every
                    # template tripped the model ended at zero attempts and the
                    # container reported SKIPPED with exit code 0. Counting it also
                    # makes a single occurrence visible to
                    # --fail-on-incomplete-scanners, which reads targets_failed.
                    self.targets_attempted += 1
                    self.targets_failed += 1
                    reason = (
                        "the template carries a Resources mapping but could not be "
                        f"modeled as CloudFormation: {type(e.error).__name__}"
                    )
                    self._plugin_log(
                        f"cfn_nag did not evaluate {cfn_file}: {reason}",
                        target_type=target_type,
                        level=logging.ERROR,
                    )
                    self.errors.append(f"{cfn_file}: {reason}")
                    continue
                except Exception as e:
                    # Everything else here comes out of load_yaml, i.e. the file is not
                    # parseable as YAML or JSON and so was never a candidate template.
                    self._plugin_log(
                        f"Not a CloudFormation file: {cfn_file}. Exception: {e}",
                        target_type=target_type,
                        level=logging.TRACE,
                    )
                    continue
                if cfn_model is None:
                    self._plugin_log(
                        f"Not a CloudFormation file: {cfn_file}",
                        target_type=target_type,
                        level=logging.TRACE,
                    )
                    continue
                # Counted here rather than at the top of the loop: the two continues above
                # are non-CloudFormation files, which are an expected skip rather than a
                # scanner failure.
                self.targets_attempted += 1
                normalized_filename = get_normalized_filename(str_to_normalize=cfn_file)
                results_file_dir = target_results_dir.joinpath(normalized_filename)
                results_file_dir.mkdir(exist_ok=True, parents=True)
                final_args = self._resolve_arguments(
                    target=cfn_file, results_file=results_file_dir
                )
                proc_resp = self._run_subprocess(
                    command=final_args,
                    results_dir=results_file_dir,
                    stdout_preference="both",
                    stderr_preference="both",
                    timeout=self._effective_scan_timeout(),
                )
                try:
                    stdout = proc_resp.get("stdout", "")
                    if not stdout or not stdout.strip():
                        reason = (
                            "cfn_nag returned no stdout "
                            f"(exit code {proc_resp.get('returncode', '?')})"
                        )
                        # error, not debug: no rule was evaluated against this template, and
                        # at debug level that was invisible on a default run.
                        ASH_LOGGER.error(f"CFN Nag returned no stdout for {cfn_file}")
                        self.targets_failed += 1
                        self.errors.append(f"{cfn_file}: {reason}")
                        unrendered.append(cfn_file)
                        continue
                    file_sarif = SarifReport.model_validate_json(json_data=stdout)
                    if self._evaluated_no_rule(file_sarif, proc_resp.get("returncode")):
                        reason = (
                            "cfn_nag reported a failure it could not render "
                            f"(exit code {proc_resp.get('returncode', '?')} with an "
                            "empty result set), which means no rule was evaluated "
                            "against this template"
                        )
                        ASH_LOGGER.error(
                            f"CFN Nag did not evaluate {cfn_file}: {reason}"
                        )
                        self.targets_failed += 1
                        self.errors.append(f"{cfn_file}: {reason}")
                        continue
                    if sarif_report is None and file_sarif is not None:
                        sarif_report = file_sarif
                    elif file_sarif is not None:
                        sarif_report.merge_sarif_report(
                            sarif_report=file_sarif,
                            include_invocation=False,
                            include_driver=False,
                            # CFN Nag includes the full rule list regardless if there were
                            # results matching the rule ID.
                            # Since `include_driver=True`, it will include the rule list
                            # when it attaches the initial driver.
                            include_rules=False,
                        )
                except Exception as e:
                    ASH_LOGGER.warning(
                        f"Failed to parse CFN Nag results as SARIF: {str(e)}"
                    )
                    self.targets_failed += 1
                    self.errors.append(f"{cfn_file}: {type(e).__name__}: {e}")
                    continue

            # Every template failed. This is the one line that separates "your templates are
            # compliant" from "cfn_nag never evaluated a rule"; the reports are otherwise
            # identical. The zero case stays a success, because a run with no CloudFormation
            # in it completed fine and carries that fact as a SKIPPED status instead.
            if (
                self.targets_attempted > 0
                and self.targets_failed >= self.targets_attempted
            ):
                ASH_LOGGER.error(
                    f"cfn_nag failed on all {self.targets_attempted} template(s) in "
                    f"{target}. No rules were evaluated, so this result is NOT a clean scan."
                )

            self._post_scan(
                target=target,
                target_type=target_type,
            )

            sarif_invocation: Invocation = Invocation(
                commandLine="ash-CFN Nag-scanner",
                arguments=[
                    "--target",
                    get_shortest_name(input=target),
                    "--scanner",
                ],
                startTimeUtc=self.start_time,
                endTimeUtc=self.end_time,
                executionSuccessful=(self.exit_code == 0 or self.exit_code == 1),
                exitCode=self.exit_code,
                exitCodeDescription="\n".join(self.errors),
                workingDirectory=ArtifactLocation(
                    uri=get_shortest_name(input=target),
                ),
                properties=PropertyBag(
                    tool=sarif_tool,
                ),
            )
            if sarif_report.runs:
                sarif_report.runs[0].invocations = [sarif_invocation]
            with open(sarif_output_file, mode="w", encoding="utf-8") as fp:
                report_str = sarif_report.model_dump_json(
                    exclude_none=True,
                    exclude_unset=True,
                )
                fp.write(report_str)

            if unrendered:
                # A hard scanner failure rather than one failed target among many, and
                # the distinction is the whole reason this raises. cfn_nag_scan is
                # invoked once per template and always writes a document, so an
                # invocation that produced zero bytes did not fail to find anything --
                # it failed to run, and the process dying before rendering is a property
                # of the tool rather than of one template. Left as a target counter, one
                # crashed template among nine clean ones keeps targets_failed below
                # targets_attempted, determine_status falls through to the severity gate
                # over the surviving findings, and the scanner reports PASSED with the
                # crashed template's findings absent and one ERROR line as the only
                # record.
                #
                # Raised here, after _post_scan and after the report is on disk, so the
                # timings are recorded and the findings from the templates that did scan
                # are not thrown away with the verdict.
                raise ScannerError(
                    "cfn_nag_scan produced no output for "
                    f"{len(unrendered)} of {self.targets_attempted} template(s), so "
                    "no rule was evaluated against them and this run is not a clean "
                    f"scan: {', '.join(unrendered)}"
                )

            return sarif_report

        except Exception as e:
            # Check if there are useful error details
            raise ScannerError(f"{self.__class__.__name__} failed: {str(e)}")


if __name__ == "__main__":
    scanner = CfnNagScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
    )
    report = scanner.scan(target=scanner.source_dir)

    report_json = report.model_dump_json(
        indent=2,
        by_alias=True,
        exclude_unset=True,
    )
    with open(
        Path.cwd().joinpath(".ash", "ash_output").joinpath("cfn_nag_results.sarif"), "w"
    ) as f:
        f.write(report_json)
