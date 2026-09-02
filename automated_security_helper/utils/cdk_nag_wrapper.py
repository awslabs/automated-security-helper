# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import inspect
import re
import json
import threading
from pathlib import Path
from typing import Dict, List, Literal

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Kind,
    Level,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
)
from automated_security_helper.utils.cfn_template_model import (
    CloudFormationTemplateModel,
    get_model_from_template,
)
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.schemas.sarif_schema_model import Location
from cfn_tools import dump_yaml
from automated_security_helper.utils.log import ASH_LOGGER


class CdkNagWrapperResponse:
    def __init__(
        self,
        results: Dict[str, List[Result]] | None = None,
        outdir: Path | None = None,
        template: CloudFormationTemplateModel | None = None,
    ):
        self.results = results
        self.outdir = outdir
        self.template = template


_env_lock = threading.Lock()


def _build_nag_pack(pack_name: str):
    """Construct one nag pack by class name.

    Extracted to module level so a test can assert that the keyword arguments passed here are
    ones the installed cdk-nag actually accepts. That single line is where a breaking major
    bump lands, and while it was buried inside the per-template loop the only way to exercise
    it was a full synthesis -- which nothing in the suite did.

    ``verbose=True`` is the only property worth setting: as of cdk-nag 3.x ``NagPackProps``
    has exactly ``verbose`` and ``writeSuppressionsToCloudFormation``. Earlier majors also
    accepted ``reports`` and ``reportFormats``, which drove a file-based report; v3 replaced
    that with CDK's policy validation report, so passing them now raises TypeError.
    """
    import cdk_nag

    pack_type = getattr(cdk_nag, pack_name, None)
    if pack_type is None:
        raise ValueError(f"Unknown cdk-nag pack: {pack_name}")
    return pack_type(verbose=True)


class _NagFinding:
    """One cdk-nag violation, exposing the field names the downstream mapping reads.

    Mirrors the attribute surface of cdk-nag 2.x's ``NagReportLine`` (``rule_id``,
    ``resource_id``, ``compliance``, ``exception_reason``, ``rule_level``, ``rule_info``) so
    the SARIF construction below is untouched by the v3 migration. ``NagReportLine`` itself is
    not used because v3 no longer ships the file-report schema it belonged to.
    """

    __slots__ = (
        "rule_id",
        "resource_id",
        "compliance",
        "exception_reason",
        "rule_level",
        "rule_info",
    )

    def __init__(
        self,
        rule_id: str,
        resource_id: str,
        compliance: str,
        exception_reason: str,
        rule_level: str,
        rule_info: str,
    ) -> None:
        self.rule_id = rule_id
        self.resource_id = resource_id
        self.compliance = compliance
        self.exception_reason = exception_reason
        self.rule_level = rule_level
        self.rule_info = rule_info

    def as_dict(self) -> Dict[str, str]:
        """The raw finding record, attached to the SARIF result's property bag.

        Kept a plain dict because the scanner reads it back out of
        ``result.properties.model_extra["cdk_nag_finding"]`` and indexes it by these keys.
        """
        return {
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "compliance": self.compliance,
            "exception_reason": self.exception_reason,
            "rule_level": self.rule_level,
            "rule_info": self.rule_info,
        }


def _normalize_rule_level(severity: str) -> str:
    """Map a v3 severity onto the capitalized level the SARIF mapping compares against.

    This matters more than it looks. The SARIF construction below tests
    ``rule_level == "Error"``, while the validation report emits ``"error"`` in lower case.
    Passing the raw value through would classify every finding as a warning, quietly demoting
    real errors below a severity gate and turning a failing scan into a passing one.
    """
    normalized = (severity or "").strip().lower()
    return {"error": "Error", "warning": "Warning", "info": "Info"}.get(
        normalized, "Error" if normalized else "Error"
    )


def _violations_from_validation_report(
    report_path: Path,
) -> Dict[str, List["_NagFinding"]]:
    """Read CDK's policy validation report into per-pack normalized finding dicts.

    Replaces the ``*-NagReport.json`` reader used with cdk-nag 2.x. In v3 the packs are
    ``IPolicyValidationPlugin`` implementations rather than aspects, and their output lands in
    a single ``validation-report.json`` written by CDK, keyed by plugin.

    The returned shape deliberately matches the fields the downstream mapping already
    consumes, so the resource lookup and template line-number search are reused rather than
    rewritten. That mapping depends on the last path segment of the construct path being the
    template's logical ID, which holds under CfnInclude -- measured as
    ``ASHCDKNagScanner/<template>/<LogicalId>``.

    One behavior change that cannot be preserved: the validation report contains violations
    only, so there is no compliant-check record to return. Callers asking for compliant checks
    get nothing rather than a wrong answer.
    """
    if not report_path.exists():
        ASH_LOGGER.error(
            f"cdk-nag produced no validation report at {report_path}. No rules were "
            "evaluated, so this template was NOT scanned."
        )
        return {}

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        ASH_LOGGER.error(f"Could not parse cdk-nag validation report {report_path}: {exc}")
        return {}

    per_pack: Dict[str, List[_NagFinding]] = {}
    for plugin_report in report.get("pluginReports", []) or []:
        pack_name = plugin_report.get("pluginName") or "cdk-nag"
        rows = per_pack.setdefault(pack_name, [])
        for violation in plugin_report.get("violations", []) or []:
            rule_id = violation.get("ruleName") or ""
            rule_info = violation.get("description") or ""
            rule_level = _normalize_rule_level(violation.get("severity", ""))
            # One violation can cite several constructs; each becomes its own finding so the
            # SARIF result points at a single resource, as it did under 2.x.
            for construct in violation.get("violatingConstructs", []) or []:
                construct_path = construct.get("constructPath") or ""
                if not construct_path:
                    continue
                rows.append(
                    _NagFinding(
                        rule_id=rule_id,
                        resource_id=construct_path,
                        # The validation report carries violations only. "Non-Compliant" is
                        # therefore the sole possible value, and include_compliant_checks has
                        # nothing to include -- see the note in the docstring.
                        compliance="Non-Compliant",
                        exception_reason="N/A",
                        rule_level=rule_level,
                        rule_info=rule_info,
                    )
                )

    total = sum(len(v) for v in per_pack.values())
    ASH_LOGGER.debug(
        f"cdk-nag validation report: {len(per_pack)} pack(s), {total} violation record(s)"
    )
    return per_pack


def run_cdk_nag_against_cfn_template(
    template_path: Path,
    nag_packs: List[
        Literal[
            "AwsSolutionsChecks",
            "HIPAASecurityChecks",
            "NIST80053R4Checks",
            "NIST80053R5Checks",
            "PCIDSS321Checks",
        ]
    ]
    | None = None,
    outdir: Path | None = None,
    include_compliant_checks: bool = False,
    stack_name: str = "ASHCDKNagScanner",
) -> CdkNagWrapperResponse | None:
    if nag_packs is None:
        nag_packs = ["AwsSolutionsChecks"]
    results: Dict[str, List[dict]] = {}

    # JSII (used by cdk_nag) reads these env vars at Python module import
    # time, so we can't pass them via env= to a subprocess — we have to
    # set them in this process. Snapshot the original values so we can
    # restore them in the finally block and not leak into the parent
    # process after the scan (scanners run in parallel threads, so
    # permanent writes would race with other work).
    # A lock serialises the save-modify-execute-restore cycle so that
    # parallel ThreadPoolExecutor invocations don't clobber each other.
    with _env_lock:
        _jsii_env_keys = (
            "NODE_NO_WARNINGS",
            "JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION",
            "JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION",
        )
        _original_jsii_env = {k: os.environ.get(k) for k in _jsii_env_keys}
        for _k in _jsii_env_keys:
            os.environ[_k] = "1"

        # Suppress JSII stack traces by redirecting stderr for entire function
        import sys

        original_stderr = sys.stderr
        devnull_file = None
        try:
            devnull_file = open(os.devnull, "w")
            sys.stderr = devnull_file

            try:
                import cdk_nag
            except (ImportError, FileNotFoundError):
                sys.stderr = original_stderr
                ASH_LOGGER.warning(
                    "NodeJS is missing and CDK Nag depends on it due to transitive dependencies. "
                    "Please install NodeJS and try running your ASH scan again for CDK NagPack coverage on CloudFormation templates. "
                )
                return None
            from aws_cdk import (
                App,
                Stack,
                Validations,
            )
            from aws_cdk.cloudformation_include import (
                CfnInclude,
            )
            from constructs import Construct

            class WrapperStack(Stack):
                def __init__(
                    self,
                    scope: Construct | None = None,
                    id: str | None = None,
                    template_path: Path | None = None,
                ):
                    if template_path is None:
                        raise ValueError("template_path must be provided")
                    if not template_path.exists():
                        raise FileNotFoundError(
                            f"Template file does not exist: {template_path}"
                        )
                    super().__init__(scope, id)
                    # Get the relative path to use as the logical ID
                    # CDK will replace path separators with
                    try:
                        logical_id = get_shortest_name(input=template_path)
                    except ValueError:
                        logical_id = Path(template_path).as_posix()
                    CfnInclude(
                        self,
                        id=logical_id,
                        template_file=Path(template_path).as_posix(),
                    )

            # Enumerate all classes in `cdk_nag`, identify any that extend `NagPack`
            def get_nag_packs():
                nag_packs = {}
                for item in dir(cdk_nag):
                    # get class from cdk_nag
                    pack = getattr(cdk_nag, item)
                    if inspect.isclass(pack) and issubclass(pack, cdk_nag.NagPack):
                        nag_packs[item] = {
                            "packType": pack,
                        }
                return nag_packs

            model = get_model_from_template(template_path)
            if model is None:
                ASH_LOGGER.debug(
                    "No model validated from template, skipping CDK Nag. This does not seem to be a valid CloudFormation template"
                )
                return None

            ASH_LOGGER.debug(f"Validated model from template: {model}")
            ASH_LOGGER.debug(f"outdir: {outdir.as_posix() if outdir else 'None'}")
            clean_template_filename = Path(template_path).as_posix()
            try:
                clean_template_filename = get_shortest_name(input=template_path)
            except ValueError as e:
                ASH_LOGGER.debug(f"Could not get relative path to template: {e}")
                clean_template_filename = Path(template_path).as_posix()
            except Exception as e:
                ASH_LOGGER.debug(f"Could not get relative path to template: {e}")
                clean_template_filename = Path(template_path).as_posix()
            ASH_LOGGER.debug(f"clean_template_filename: {clean_template_filename}")
            clean_template_filename = re.sub(
                r"(\/|\\|\.)+", "--", clean_template_filename.lstrip("/")
            )
            ASH_LOGGER.debug(f"clean_template_filename: {clean_template_filename}")
            if outdir is None:
                raise ValueError("outdir is required for cdk_nag scanning")
            ASH_LOGGER.debug(f"cdk nag outdir pre: {outdir.__str__()}")
            outdir = outdir.joinpath(clean_template_filename)
            ASH_LOGGER.debug(f"cdk nag outdir post: {outdir.__str__()}")
            outdir.mkdir(parents=True, exist_ok=True)
            ASH_LOGGER.debug("outdir cleaned, creating CDK wrapper app")

            app = App(
                outdir=outdir.as_posix(),
            )

            nag_pack_lookup = get_nag_packs()
            stack = WrapperStack(
                app,
                stack_name,
                template_path=template_path,
            )

            with open(template_path, mode="r", encoding="utf-8") as f:
                template_lines = f.readlines()

            # Registered as policy validation plugins on the APP, not as aspects on the stack.
            #
            # cdk-nag 2.x packs implemented IAspect and were added with
            # Aspects.of(stack).add(...). From 3.0.0 they implement IPolicyValidationPlugin
            # instead -- `hasattr(pack, "visit")` is False and `hasattr(pack, "validate")` is
            # True -- so an aspect registration attaches nothing and evaluates no rules.
            registered = 0
            for pack in nag_packs:
                if pack not in nag_pack_lookup:
                    ASH_LOGGER.error(f"Unknown cdk-nag pack requested: {pack}")
                    continue
                ASH_LOGGER.debug(f"Adding nag pack '{pack}'")
                Validations.of(app).add_plugins(_build_nag_pack(pack))
                registered += 1

            if registered == 0:
                # No pack means no rule can fire, which would otherwise yield an empty report
                # indistinguishable from a compliant template.
                ASH_LOGGER.error(
                    f"No cdk-nag packs were registered for {template_path}; nothing was "
                    "evaluated."
                )
                return None

            # Synth is where validation runs, and CDK raises when a plugin reports violations.
            # For this wrapper a raise is the ordinary case -- findings are the product -- so
            # it is caught and the report is read regardless. Letting it propagate would turn
            # every non-compliant template into a scanner error.
            try:
                app.synth()
            except Exception as exc:
                ASH_LOGGER.debug(
                    f"cdk-nag validation reported violations during synth for "
                    f"{template_path}: {type(exc).__name__}"
                )
            outdir = app.outdir
            ASH_LOGGER.debug(f"app.outdir: {outdir}")

            # cfn_inc: CfnInclude = item in stack.node.children[0]
            included = [
                item for item in stack.node.children if isinstance(item, CfnInclude)
            ]
            ASH_LOGGER.debug(json.dumps(included, default=str, indent=2))

            results: Dict[str, List[Result]] = {}

            # cdk-nag 3.x reports through CDK's policy validation framework, which writes a
            # single validation-report.json rather than the per-pack *-NagReport.json files
            # 2.x produced. Globbing for those files against a v3 install finds nothing and
            # yields an empty result set -- a scan that looks clean because it read the wrong
            # place.
            cdk_nag_report_lines = _violations_from_validation_report(
                Path(outdir) / "validation-report.json"
            )

            if not cdk_nag_report_lines:
                ASH_LOGGER.debug(
                    f"cdk-nag reported no violations for {template_path}"
                )

            for pack_name, report_lines in cdk_nag_report_lines.items():
                if pack_name not in results:
                    results[pack_name] = []
                line: _NagFinding
                for line in report_lines:
                    if line.compliance == "Compliant" and not include_compliant_checks:
                        ASH_LOGGER.debug(f"Skipping compliant check: {line.rule_id}")
                        continue

                    # Under CfnInclude the construct path is
                    # "<stack>/<template>/<LogicalId>", so the last segment is the template's
                    # own logical ID -- the same property 2.x's resourceId had, which is why
                    # the lookup and line-number search below are unchanged.
                    resource_log_id = line.resource_id.split("/")[-1]

                    cfn_file_rel_path = get_shortest_name(input=template_path)
                    cfn_resource_matches = [
                        item
                        for resource_id, item in model.Resources.items()
                        if resource_id == resource_log_id
                    ]
                    if not cfn_resource_matches:
                        continue
                    cfn_resource = cfn_resource_matches[0]
                    # Get location in `template_lines` of line number and column
                    # number of the resource_log_id
                    resource_line = None
                    resource_column = None
                    resource_log_id_pattern = re.compile(
                        r"(?<![a-zA-Z0-9_])" + re.escape(resource_log_id) + r"(?![a-zA-Z0-9_])"
                    )
                    for i, line_str in enumerate(template_lines, start=1):
                        match = resource_log_id_pattern.search(line_str)
                        if match:
                            resource_line = i
                            resource_column = match.start()
                            break

                    cfn_resource_dict = {
                        "Resources": {
                            resource_log_id: cfn_resource.model_dump(by_alias=True)
                        }
                    }
                    finding = Result(
                        properties=PropertyBag(
                            cdk_nag_finding=line.as_dict(),
                            cfn_resource=cfn_resource_dict,
                            tags=[
                                "aws",
                                "cdk",
                                "cdk-nag",
                                pack_name,
                                line.rule_id,
                                resource_log_id,
                                cfn_resource.Type,
                                "tool_name::cdk-nag",
                                "tool_type::IAC",
                            ],
                        ),
                        ruleId=line.rule_id,
                        level=(
                            Level.error
                            if line.compliance == "Non-Compliant"
                            and line.rule_level == "Error"
                            else (
                                Level.warning
                                if line.compliance == "Non-Compliant"
                                and line.rule_level != "Error"
                                else Level.none
                            )
                        ),
                        kind=(
                            Kind.fail
                            if line.compliance == "Non-Compliant"
                            and line.rule_level == "Error"
                            else (
                                Kind.review
                                if line.compliance == "Suppressed"
                                and line.exception_reason != "N/A"
                                else Kind.informational
                            )
                        ),
                        message=Message(
                            root=Message1(
                                text=f"{line.rule_info}\n\nException Reason: {line.exception_reason}"
                            )
                        ),
                        analysisTarget=ArtifactLocation(
                            uri=cfn_file_rel_path,
                        ),
                        locations=[
                            Location(
                                id=1,
                                physicalLocation=PhysicalLocation(
                                    root=PhysicalLocation2(
                                        artifactLocation=ArtifactLocation(
                                            uri=get_shortest_name(input=template_path),
                                        ),
                                        region=Region(
                                            startLine=(resource_line or 1),
                                            endLine=(resource_line or 1),
                                            startColumn=(resource_column or 1),
                                            endColumn=(resource_column or 1)
                                            + len(resource_log_id),
                                            snippet=ArtifactContent(
                                                text=dump_yaml(
                                                    {
                                                        "Resources": {
                                                            resource_log_id: cfn_resource.model_dump(
                                                                by_alias=True
                                                            )
                                                        }
                                                    }
                                                )
                                            ),
                                        ),
                                    ),
                                ),
                            )
                        ],
                    )

                    results[pack_name].append(finding)

            return CdkNagWrapperResponse(results=results, outdir=outdir, template=model)
        finally:
            sys.stderr = original_stderr
            if devnull_file:
                devnull_file.close()
            # Restore JSII-related env vars so we don't leak into the parent
            # process. Vars that didn't exist originally are removed.
            for _k, _orig in _original_jsii_env.items():
                if _orig is None:
                    os.environ.pop(_k, None)
                else:
                    os.environ[_k] = _orig


if __name__ == "__main__":
    ASH_LOGGER.debug("Running cdk_nag against test template")
    template_path = (
        Path(__file__)
        .parent.parent.parent.parent.joinpath("tests")
        .joinpath("test_data")
        .joinpath("scanners")
        .joinpath("cdk")
        .joinpath("secure-s3-template")
        .joinpath("secure-s3-template.yaml")
    )
    res = run_cdk_nag_against_cfn_template(
        template_path=template_path,
        nag_packs=[
            "AwsSolutionsChecks",
            "HIPAASecurityChecks",
            "NIST80053R4Checks",
            "NIST80053R5Checks",
            "PCIDSS321Checks",
        ],
        outdir=Path(__file__)
        .parent.parent.parent.parent.joinpath(".ash", "ash_output")
        .joinpath("scanners")
        .joinpath("cdknag"),
    )

