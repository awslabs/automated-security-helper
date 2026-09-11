"""Module containing the CDK Nag security scanner implementation."""

import logging
import re
from importlib.metadata import PackageNotFoundError, packages_distributions, requires
from typing import Annotated, ClassVar, List, Literal
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    MultiformatMessageString,
    PropertyBag,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.utils.get_ash_version import get_ash_version
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.subprocess_utils import find_executable

#: Every distribution ASH's ``cdk`` extra installs. All three have to be present
#: for the wrapper to get as far as evaluating a rule: ``cdk_nag`` supplies the
#: packs, ``aws-cdk-lib`` the App/Stack/CfnInclude the wrapper synthesizes, and
#: ``constructs`` the base class both of those are built on.
#:
#: Kept as a literal tuple rather than derived from ``_cdk_extra_requirements()``
#: below. That function reads pyproject's own metadata, which is the right source
#: for *what to install* but the wrong one for *what to probe*: it falls back to a
#: pinned list when the metadata is unreadable, and probing a fallback would let a
#: checkout with no distribution metadata at all report every dependency present.
_CDK_REQUIRED_DISTRIBUTIONS = ("cdk_nag", "aws-cdk-lib", "constructs")


def _missing_cdk_distributions(
    distributions: "tuple[str, ...]" = _CDK_REQUIRED_DISTRIBUTIONS,
) -> List[str]:
    """Which of ``distributions`` have no installed metadata, in declared order.

    A metadata read, not an import. The alternative -- importing ``cdk_nag`` here
    to prove it works -- was rejected on cost: this module is imported during
    plugin discovery on every ASH invocation, including ``ash --help`` and runs
    that never select cdk-nag, and importing cdk_nag starts a jsii kernel, which
    spawns a NodeJS child process. Paying that on every invocation to sharpen one
    scanner's availability check is the wrong trade.

    What the metadata read cannot see is a state where all three distributions are
    installed but importing them still fails -- a half-finished pip run, a missing
    jsii transitive dependency, NodeJS absent. That case is not left silent: the
    wrapper's own import guard reports the failure per template, which the scanner
    records against the target it was scanning.

    Probing all three rather than only ``cdk_nag`` is the point of this function.
    A one-distribution probe passes on an install where cdk-nag is present and
    aws-cdk-lib is not -- reproducible with ``pip install --no-deps cdk-nag`` --
    and every template then failed to import, decremented the attempt count back
    toward zero, and the scan reported SKIPPED with exit code 0 while both
    completeness gates passed it. ``get_installation_commands`` gates on the same
    flag, so the documented remediation was a no-op in exactly that state too.
    """
    from importlib.metadata import version as _dist_version

    missing: List[str] = []
    for distribution in distributions:
        try:
            _dist_version(distribution)
        except Exception:
            # Broad on purpose. PackageNotFoundError is the expected answer, but a
            # malformed *.dist-info on sys.path raises other things, and any
            # failure to confirm the distribution is present has to read as "not
            # present" -- resolving an unreadable install to "available" is the
            # defect this probe exists to remove.
            missing.append(distribution)
    return missing


#: Populated at import time so ``validate_plugin_dependencies`` can name what is
#: absent instead of listing all three whatever the actual state is. Empty when
#: ``_CDK_AVAILABLE`` is False because the *wrapper import* failed rather than
#: because a distribution is missing, which is why the warning below has a
#: fallback.
_CDK_MISSING_DISTRIBUTIONS: List[str] = _missing_cdk_distributions()
_CDK_AVAILABLE = not _CDK_MISSING_DISTRIBUTIONS
_cdk_nag_version = "unavailable"
run_cdk_nag_against_cfn_template = None  # type: ignore[assignment]

if _CDK_AVAILABLE:
    try:
        from importlib.metadata import version as _get_version

        _cdk_nag_version = _get_version("cdk_nag")
        from automated_security_helper.utils.cdk_nag_wrapper import (
            run_cdk_nag_against_cfn_template,
        )
    except Exception:
        _CDK_AVAILABLE = False
        _cdk_nag_version = "unavailable"
        run_cdk_nag_against_cfn_template = None  # type: ignore[assignment]


# Last-resort copy of the "cdk" extra's contents. The source of truth is
# [project.optional-dependencies] cdk in pyproject.toml; this list duplicates it
# and can therefore go stale, which is exactly why it is only reached when the
# metadata read below fails outright.
_CDK_EXTRA_FALLBACK_REQUIREMENTS: List[str] = [
    "aws-cdk-lib>=2.268.0,<3.0.0",
    "cdk-nag>=3.0,<4.0.0",
    "constructs>=10.8,<11.0.0",
]

# Matches the ``extra == "cdk"`` half of a PEP 508 marker. importlib.metadata
# renders the marker with single quotes while pyproject.toml and pip emit double
# quotes, so neither style can be assumed.
_CDK_EXTRA_MARKER = re.compile(r"""\bextra\s*==\s*['"]cdk['"]""")


def _cdk_extra_requirements() -> List[str]:
    """Return the third-party requirements that make up ASH's ``cdk`` extra.

    Reads them out of the installed distribution's own metadata so that changing
    a bound in pyproject.toml cannot leave this installer resolving versions
    nobody has looked at since. A hardcoded list was rejected as the primary
    source for that reason; it survives only as the fallback below.

    The distribution is located by asking which distribution provides *this
    module's* top-level package, never by naming one. A literal distribution
    name is a name someone else can own on a package index, and installing by
    such a name is the defect this function exists to remove.

    Never returns an empty list. This function is only reached when cdk-nag is
    already missing, so an empty result means ``ash dependencies install`` runs
    no pip command, exits 0, and leaves cdk-nag MISSING -- which is precisely
    the defect it exists to remove. An empty accumulation therefore falls
    through to the pinned fallback rather than being reported as "nothing to
    install".

    Why every mapped distribution is searched, not just the first
    ------------------------------------------------------------
    ``packages_distributions()`` maps a top-level package name to a *list* of
    distributions providing it. An earlier version returned on the first entry
    whose ``requires()`` was not None, whether or not any of its requirements
    carried the ``extra == "cdk"`` marker. One shadowing or stale
    ``*.dist-info`` that declares requirements but no ``cdk`` extra -- the
    ordinary result of an editable install left behind next to a real one --
    then yielded ``[]``, and the install silently did nothing. Accumulating
    across all of them and only returning a non-empty result means a stale entry
    can no longer mask a good one.

    Why the try/except is inside the loop, and why ValueError is caught
    ------------------------------------------------------------------
    Both were found by probing rather than by reading. ``requires()`` returns
    None for an unreadable or absent ``METADATA`` instead of raising, so the
    handler does not fire for the case the previous docstring credited it with:
    ASH run from a checkout that was never installed has no mapping at all,
    ``.get()`` returns None, the loop body never executes, and the fallback is
    reached by the normal path.

    What the handlers do catch is narrower and real. ``packages_distributions()``
    walks every entry on ``sys.path`` and raises ``OSError`` on an unreadable
    one, which is why that call keeps its own handler -- moving all the handling
    inside the loop was tried and let that OSError escape into
    ``ash dependencies install`` as a traceback. Separately, ``requires()``
    raises ``PackageNotFoundError`` for a name that stops resolving between the
    two calls -- a concurrent uninstall, or an editable install being rebuilt.
    And a ``*.dist-info`` carrying a ``top_level.txt`` but no ``METADATA`` makes
    ``packages_distributions()`` yield ``[None]``; ``requires(None)`` raises
    ``ValueError: A distribution name is required``, which the previous
    two-exception clause did not catch, so one broken sibling distribution
    crashed the command outright. The per-name handler is inside the loop so that
    one unreadable distribution no longer discards what the others declared.
    """
    root_package = __name__.split(".", 1)[0]
    accumulated: List[str] = []
    try:
        dist_names = packages_distributions().get(root_package) or []
    except (PackageNotFoundError, OSError) as exc:
        ASH_LOGGER.debug(
            f"Could not enumerate the distributions providing {root_package!r} "
            f"({exc}); falling back to the pinned requirement list."
        )
        return list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)

    for dist_name in dist_names:
        try:
            declared = requires(dist_name)
        except (PackageNotFoundError, OSError, ValueError) as exc:
            ASH_LOGGER.debug(
                f"Could not read requirements from distribution {dist_name!r} "
                f"providing {root_package!r} ({exc}); skipping it."
            )
            continue
        if declared is None:
            continue
        for requirement in declared:
            if not _CDK_EXTRA_MARKER.search(requirement):
                continue
            # Keep the requirement, drop the marker. pip evaluates markers with
            # ``extra`` undefined, so ``extra == "cdk"`` is false and pip skips
            # the requirement while still exiting 0 -- an install that reports
            # success and installs nothing.
            bare = requirement.split(";", 1)[0].strip()
            # Deduplicated in place rather than through a set, so the order
            # pyproject.toml declares is what pip receives. A set would make the
            # generated command vary run to run, which is noise in any log that
            # records it.
            if bare and bare not in accumulated:
                accumulated.append(bare)

    if accumulated:
        return accumulated

    ASH_LOGGER.debug(
        f"No 'extra == \"cdk\"' requirements found in the metadata of any "
        f"distribution providing {root_package!r}; falling back to the pinned "
        f"requirement list."
    )
    return list(_CDK_EXTRA_FALLBACK_REQUIREMENTS)


class CdkNagPacks(BaseModel):
    model_config = ConfigDict(extra="allow")

    AwsSolutionsChecks: Annotated[
        bool,
        Field(description="Runs the AwsSolutionsChecks NagPack included with CDK Nag."),
    ] = True
    HIPAASecurityChecks: Annotated[
        bool,
        Field(
            description="Runs the HIPAASecurityChecks NagPack included with CDK Nag."
        ),
    ] = False
    NIST80053R4Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R4Checks NagPack included with CDK Nag."),
    ] = False
    NIST80053R5Checks: Annotated[
        bool,
        Field(description="Runs the NIST80053R5Checks NagPack included with CDK Nag."),
    ] = False
    PCIDSS321Checks: Annotated[
        bool,
        Field(description="Runs the PCIDSS321Checks NagPack included with CDK Nag."),
    ] = False


class CdkNagScannerConfigOptions(ScannerOptionsBase):
    """CDK Nag IAC SAST scanner options."""

    nag_packs: Annotated[
        CdkNagPacks,
        Field(
            description="CDK Nag packs to enable",
        ),
    ] = CdkNagPacks()
    include_compliant_checks: Annotated[
        bool,
        Field(
            description="Include INFO-level findings for compliant resources in the report.",
        ),
    ] = False


class CdkNagScannerConfig(ScannerPluginConfigBase):
    name: Literal["cdk-nag"] = "cdk-nag"
    enabled: bool = True
    options: Annotated[
        CdkNagScannerConfigOptions, Field(description="Configure Bandit scanner")
    ] = CdkNagScannerConfigOptions()


@ash_scanner_plugin
class CdkNagScanner(ScannerPluginBase[CdkNagScannerConfig]):
    """CDK Nag security scanner, custom CDK-CLI-less implementation."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        if self.config is None:
            self.config = CdkNagScannerConfig()
        self.command = "python"
        self.tool_type = ScannerToolType.IAC
        self.description = "CDK Nag is a security scanner for AWS CloudFormation templates that applies industry standard checks against AWS infrastructure-as-code."
        self.tool_version = _cdk_nag_version
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        if not _CDK_AVAILABLE:
            # Names what is actually absent. Listing all three unconditionally
            # described a partial install wrongly, and a wrong list is worse than
            # none here: an operator who can see cdk-nag in `pip list` reads
            # "cdk-nag is not installed" as a bug in ASH and stops reading.
            #
            # Points at ASH's own command rather than at a pip install of
            # "automated-security-helper[cdk]". That name belongs to an
            # unrelated project on PyPI, so the old hint sent users to install a
            # stranger's package to fix an ASH problem.
            absent = ", ".join(_CDK_MISSING_DISTRIBUTIONS) or ", ".join(
                _CDK_REQUIRED_DISTRIBUTIONS
            )
            ASH_LOGGER.warning(
                f"CDK dependencies are not usable ({absent} unavailable). "
                "Install them with: ash dependencies install"
            )
            self.dependencies_satisfied = False
            return False
        found = find_executable("node")
        return found is not None

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """Install the third-party packages behind ASH's ``cdk`` extra.

        Names aws-cdk-lib, cdk-nag and constructs directly. This method used to
        install ``automated-security-helper[cdk]`` instead, which made
        ``ash dependencies install`` resolve a distribution by that name from
        whatever index pip is pointed at. ASH is not published to any index --
        it installs from git, as the README documents -- so that name resolves to
        an unrelated third party's package, and it was being installed by a
        security scanner running inside CI with repository access. Naming the
        extra's real contents means this command cannot resolve ASH by name at
        all, whoever ends up owning that name.
        """
        import sys

        commands = super().get_installation_commands(platform, arch)
        if not _CDK_AVAILABLE:
            # Appended unconditionally. _cdk_extra_requirements never returns an
            # empty list, and the `if requirements:` that used to stand here was
            # what turned an empty result into a silent no-op: no pip command was
            # appended, `ash dependencies install` exited 0, and cdk-nag stayed
            # MISSING. Should that invariant ever break, pip refuses an install
            # with no arguments and exits non-zero, which is the loud failure this
            # command needs rather than a green run that installed nothing.
            #
            # One pip invocation, so the three are resolved together. Three
            # separate installs let a later one downgrade an earlier one's shared
            # transitive dependency.
            commands.append(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    *_cdk_extra_requirements(),
                ]
            )
        return commands

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — CdkNag overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CdkNagScannerConfig | None = None,
    ) -> SarifReport | bool:
        """Scan the target and return findings.

        Args:
            target: Path to scan. Can be a file or directory.

        Returns:
            IaC scan report containing findings

        Raises:
            ScannerError: If scanning fails
        """
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Per-call state, reset before anything else in the method can return.
        #
        # These are instance attributes on a plugin object that ScanPhase reuses:
        # ``_scanner_tasks`` carries one task per scanner holding ``[source, converted]``, and
        # ``ScannerExecutor._execute_scanner`` loops that list against the same instance, reading
        # the counters off it after each call. So whatever a target leaves behind is what the
        # next target starts with.
        #
        # Initializing them further down, next to the loop that increments them, reads naturally
        # and was wrong in both directions. A target returning early inherited the previous
        # target's totals -- an empty converted tree after a clean source pass reported PASSED
        # over two attempts it never made, and after a failed source pass reported ERROR for a
        # target where no file was ever opened. On the first call there was nothing to inherit,
        # so the attributes stayed unset, which is how a scanner says "I do not track targets":
        # the executor recorded no claim and the empty report resolved to PASSED, defeating the
        # SKIPPED status outright.
        #
        # Top of the method rather than merely above the empty-target check, because there are
        # three early returns above the old initialization point and the next one added would
        # have inherited the same bug. Nothing between here and the first return can be
        # meaningfully counted, so there is no ordering left to get wrong.
        #
        # The counters stay on the instance rather than moving to the per-call
        # ``ScanResultsContainer``, which would remove this class of leak by construction. The
        # container is built by the executor *around* the ``scan()`` call and is not passed in,
        # and ``scan()``'s signature is the plugin contract every scanner -- including
        # third-party ones -- implements. Threading the container through it is a breaking API
        # change, and stashing it on ``self`` instead would be the same shared mutable state
        # wearing a different name.
        self.targets_attempted = 0
        self.targets_failed = 0

        tool_component = ToolComponent(
            name="ash-cdk-nag-wrapper",
            fullName="awslabs/automated-security-helper",
            organization="Amazon Web Services",
            version=get_ash_version(),
            informationUri=ASH_DOCS_URL,
            downloadUri=ASH_REPO_URL,
        )
        sarif_report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=tool_component),
                    results=[],
                    invocations=[
                        Invocation(
                            commandLine="npm audit --json",
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
            return sarif_report

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            return False

        if not self.dependencies_satisfied:
            return False

        # Find all files to scan from the scan set
        orig_scannable = (
            [item for item in self.context.work_dir.glob("**/*.*")]
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

        # The counters are already at 0 here, set at the top of the method. Deliberately not
        # re-initialized at this point: the empty-scan-set return just below is one of four
        # places this method can leave, and an initialization sitting here covers only the ones
        # underneath it.
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
        else:
            joined_files = "\n- ".join(scannable)
            ASH_LOGGER.debug(
                f"Found {len(scannable)} JSON/YAML files:\n- {joined_files}"
            )

        # Process each template file.
        #
        # The counters set at the top of this method replace a local `failed_files` list that was
        # appended to on both failure paths and never read, so a run that failed on every
        # template still produced an empty-but-successful report. They are attributes rather than
        # locals precisely so the executor can read them and status computation can see them.
        target_rel_path = get_shortest_name(input=target)

        outdir = self.results_dir.joinpath(target_type)
        sarif_results: List[Result] = []
        for cfn_file in scannable:
            self.targets_attempted += 1
            try:
                # Run CDK synthesis for this file
                config_options: CdkNagScannerConfigOptions = (
                    CdkNagScannerConfigOptions.model_validate(self.config.options)
                )
                nag_packs = config_options.nag_packs
                if isinstance(config_options.nag_packs, CdkNagPacks):
                    nag_packs = nag_packs.model_dump(by_alias=True)

                nag_result_dict = run_cdk_nag_against_cfn_template(
                    template_path=Path(cfn_file),
                    nag_packs=[
                        item
                        for item, value in nag_packs.items()
                        if item in nag_packs and bool(value)
                    ],
                    outdir=outdir,
                    include_compliant_checks=config_options.include_compliant_checks,
                    # A template synthesized by a CDK app records that app's reviewed
                    # cdk-nag suppressions in its own resource metadata, and cdk-nag 3.x
                    # does not read them back when it re-scans the template. Honoring them
                    # is therefore ASH's job; gating on ignore_suppressions keeps the flag
                    # meaning what it says, which is that an audit sees everything the
                    # repository accepted, including what it accepted in-band.
                    #
                    # Read directly rather than through getattr(..., False).
                    # ``ignore_suppressions`` is a declared field on PluginContext, so the
                    # default can only ever be reached by the field being renamed away -- and
                    # then it silently resolves to the lenient direction, honoring every
                    # in-template suppression even on a run that asked to ignore them. A
                    # direct read raises instead, which the handler below records as a failed
                    # target: loud, and consistent with the rest of this scanner, where a
                    # target that was not evaluated as requested must never read as clean.
                    # Every other consumer of this field in the codebase reads it directly
                    # too, so this is also the house form.
                    honor_template_suppressions=not self.context.ignore_suppressions,
                )
                if nag_result_dict is None:
                    # Not counted as a failure: a non-CloudFormation file in the scan set is
                    # an expected skip, not a scanner malfunction. Counting it would make a
                    # repository of plain JSON report ERROR.
                    #
                    # Decrementing back to a running total of zero is not a silent success
                    # either. When every file in the scan set lands here the count ends at 0,
                    # which the container reads as "tracked, attempted none" and reports
                    # SKIPPED. The wrapper also returns None when no nag pack is enabled and
                    # when NodeJS is unavailable, so those two reach the same place: nothing was
                    # evaluated, and the report says so instead of rendering green.
                    self.targets_attempted -= 1
                    ASH_LOGGER.debug(f"Not a CloudFormation file: {cfn_file}")
                    continue

                if nag_result_dict.failure is not None:
                    # The wrapper ran but could not read a validation report, so no rule was
                    # evaluated against this template. Counted as a failed target because the
                    # alternative is what this branch previously did: fall through to a
                    # zero-iteration findings loop, raise nothing, and report the template as
                    # clean. With one template that also defeated the "failed on all N" guard,
                    # since no failure was ever recorded for it to count.
                    self.targets_failed += 1
                    ASH_LOGGER.error(
                        f"cdk-nag did not evaluate {cfn_file}: {nag_result_dict.failure}"
                    )
                    self.errors.append(f"{cfn_file}: {nag_result_dict.failure}")
                    continue

                for pack, findings in nag_result_dict.results.items():
                    ASH_LOGGER.debug(
                        f"Found {len(findings)} findings for {pack} on template {cfn_file}"
                    )
                    sarif_results.extend(findings)
            except Exception as e:
                # error, not trace. trace sits below debug, so this was invisible even with
                # --debug: a scanner failing on every template produced no operator-visible
                # signal anywhere.
                self.targets_failed += 1
                ASH_LOGGER.error(
                    f"cdk-nag failed to scan {cfn_file}: {type(e).__name__}: {e}"
                )
                self.errors.append(f"{cfn_file}: {type(e).__name__}: {e}")

        # Every template failed. Say so loudly here as well as through the returned status:
        # this is the one line that distinguishes "your templates are compliant" from "cdk-nag
        # never evaluated a rule", and the two produce identical reports otherwise.
        #
        # The zero case is success here, and it feeds SARIF executionSuccessful below. That
        # field is about whether the tool's run completed, not about whether it had anything to
        # look at, so a scan with an empty template set is a successful run that produced no
        # results. The "nothing was evaluated" signal is carried by the container's SKIPPED
        # status instead, which is what the summary table shows a human.
        scan_succeeded = (
            self.targets_attempted <= 0 or self.targets_failed < self.targets_attempted
        )
        if not scan_succeeded:
            ASH_LOGGER.error(
                f"cdk-nag failed on all {self.targets_attempted} template(s) in {target}. "
                "No rules were evaluated, so this result is NOT a clean scan."
            )

        self._post_scan(
            target=target,
            target_type=target_type,
        )
        # Create SARIF report
        rules: List[ReportingDescriptor] = []
        rule_map = {}
        for result in sarif_results:
            if result.ruleId in rule_map:
                continue
            rule_map[result.ruleId] = result

            finding_props = result.properties.model_extra.get("cdk_nag_finding", {})

            rules.append(
                ReportingDescriptor(
                    id=result.ruleId,
                    shortDescription=MultiformatMessageString(
                        text=result.message.root.text,
                    ),
                    fullDescription=MultiformatMessageString(
                        text=result.message.root.text,
                        markdown=result.message.root.markdown,
                    ),
                    helpUri=f"https://github.com/cdklabs/cdk-nag/blob/main/RULES.md#{str(finding_props.get('rule_level', 'rule')).lower()}s",
                    properties=PropertyBag(
                        rule_level=finding_props.get("rule_level", "unknown"),
                        rule_info=finding_props.get("rule_info", "unknown"),
                        tags=finding_props.get("tags", [])
                        + [
                            f"tool_name::{self.config.name}",
                            f"tool_type::{self.tool_type or 'UNKNOWN'}",
                        ],
                    ),
                    # help,
                )
            )
        tool = Tool(
            driver=ToolComponent(
                name="ash-cdk-nag-wrapper",
                fullName="awslabs/automated-security-helper",
                organization="Amazon Web Services",
                version=get_ash_version(),
                informationUri=ASH_DOCS_URL,
                downloadUri=ASH_REPO_URL,
                rules=rules,
            ),
        )
        report = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=tool,
                    results=sarif_results,
                    invocations=[
                        Invocation(
                            commandLine="ash",
                            arguments=[
                                "--scanner",
                                "cdk-nag",
                                "--source-dir",
                                target_rel_path,
                            ],
                            startTimeUtc=self.start_time,
                            endTimeUtc=self.end_time,
                            # Derived, not hardcoded. A SARIF run asserting success while
                            # carrying zero results is indistinguishable to any consumer from
                            # a clean scan, so a total failure has to say so here.
                            executionSuccessful=scan_succeeded,
                            exitCode=0 if scan_succeeded else 1,
                            exitCodeDescription="\n".join(self.errors),
                            workingDirectory=ArtifactLocation(
                                uri=get_shortest_name(input=self.context.source_dir),
                            ),
                            properties=PropertyBag(
                                tool=tool,
                            ),
                        ),
                    ],
                )
            ],
        )
        out_path = outdir.joinpath("ash-cdk-nag.sarif")
        outdir.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            report.model_dump_json(
                exclude_none=True,
                exclude_unset=True,
            )
        )

        return report


if __name__ == "__main__":
    ASH_LOGGER.debug("Running cdk-nag via __main__")
    scanner = CdkNagScanner(
        source_dir=Path.cwd(),
        output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        config=CdkNagScannerConfig(
            options=CdkNagScannerConfigOptions(
                nag_packs=CdkNagPacks(
                    AwsSolutionsChecks=True,
                    HIPAASecurityChecks=True,
                    NIST80053R4Checks=True,
                    NIST80053R5Checks=True,
                    PCIDSS321Checks=True,
                )
            )
        ),
    )
    report = scanner.scan(target=scanner.source_dir)

    print(
        report.model_dump_json(
            indent=2,
            by_alias=True,
            exclude_unset=True,
        )
    )
