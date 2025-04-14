# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os

from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Kind,
    Level,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
)

# noqa
os.environ["JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION"] = "1"
# noqa
os.environ["JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION"] = "1"

import inspect
import re
import shutil

from pydantic import BaseModel, ConfigDict, Field
from cfn_tools import load_yaml, dump_yaml

from automated_security_helper.schemas.sarif_schema_model import Location

import cdk_nag
import json
from pathlib import Path
from typing import Annotated, Any, Dict, List, Literal, Optional
from automated_security_helper.utils.log import ASH_LOGGER

from aws_cdk import (
    App,
    Aspects,
    Stack,
)
from aws_cdk.cloudformation_include import (
    CfnInclude,
)

from constructs import Construct


class CloudFormationResource(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        validate_default=True,
    )

    Type: Annotated[str, Field(pattern=r"^([a-zA-Z0-9:]+)$")]
    Properties: Dict[str, Any]


class CloudFormationTemplateModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        validate_default=True,
    )

    AWSTemplateFormatVersion: Optional[Literal["2010-09-09"] | None] = None
    Resources: Dict[str, CloudFormationResource]


class WrapperStack(Stack):
    def __init__(
        self,
        scope: Construct | None = None,
        id: str | None = None,
        template_path: Path | None = None,
    ):
        super().__init__(scope, id)
        # Get the relative path to use as the logical ID
        # CDK will replace path separators with
        try:
            logical_id = (
                Path(template_path).absolute().relative_to(Path.cwd()).as_posix()
            )
        except ValueError:
            logical_id = Path(template_path).as_posix()
        CfnInclude(
            self,
            id=logical_id,
            template_file=Path(template_path).as_posix(),
        )


def get_model_from_template(
    template_path: Path | None = None,
) -> CloudFormationTemplateModel | None:
    if template_path is None:
        return None

    with open(template_path, "r") as f:
        template = load_yaml(f.read())

    try:
        res = CloudFormationTemplateModel.model_validate(template)
    except Exception:
        # ASH_LOGGER.debug(f"Error validating template: {e}")
        # ASH_LOGGER.debug(f"Error validating template: {e}")
        return None
    return res


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


class CdkNagWrapperResponse:
    def __init__(
        self,
        results: Dict[str, List[Result]] | None = None,
        outdir: Path = None,
        template: CloudFormationTemplateModel | None = None,
    ):
        self.results = results
        self.outdir = outdir
        self.template = template


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
    ] = [
        "AwsSolutionsChecks",
    ],
    outdir: Path = None,
    include_compliant_checks: bool = True,
    stack_name: str = "ASHCDKNagScanner",
) -> CdkNagWrapperResponse | None:
    results: Dict[str, List[dict]] = {}

    model = get_model_from_template(template_path)
    if model is None:
        ASH_LOGGER.debug(
            "No model validated from template, skipping CDK Nag. This does not seem to be a valid CloudFormation template"
        )
        return None

    ASH_LOGGER.debug(f"Validated model from template: {model}")
    ASH_LOGGER.debug(f"outdir before check: {outdir.as_posix() if outdir else 'None'}")
    if outdir is None:
        outdir = (
            Path.cwd().joinpath("ash_output").joinpath("scanners").joinpath("cdknag")
        )
    try:
        clean_template_filename = Path(template_path).relative_to(Path.cwd()).as_posix()
    except ValueError as e:
        ASH_LOGGER.debug(f"Could not get relative path to template: {e}")
        clean_template_filename = Path(template_path).as_posix()
    except Exception as e:
        ASH_LOGGER.debug(f"Could not get relative path to template: {e}")
    ASH_LOGGER.debug(f"clean_template_filename: {clean_template_filename}")
    clean_template_filename = re.sub(
        r"(\/|\\|\.)+", "--", clean_template_filename.lstrip("/")
    )
    ASH_LOGGER.debug(f"clean_template_filename: {clean_template_filename}")
    ASH_LOGGER.debug(f"cdk nag outdir pre: {outdir.__str__()}")
    outdir = outdir.joinpath(clean_template_filename)
    ASH_LOGGER.debug(f"cdk nag outdir post: {outdir.__str__()}")
    ASH_LOGGER.debug("Cleaning up outdir")
    if outdir.exists():
        shutil.rmtree(outdir)
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

    # loggers: Sequence[MemoryLogger] = [MemoryLogger()]
    for pack in nag_packs:
        ASH_LOGGER.debug(f"Adding nag pack '{pack}'")
        pack_type: type[cdk_nag.NagPack] = nag_pack_lookup[pack]["packType"]
        pack_instance = pack_type(
            # additional_loggers=loggers,
            reports=True,
            report_formats=[
                cdk_nag.NagReportFormat.JSON,
            ],
        )
        Aspects.of(stack).add(pack_instance)

    app.synth()
    outdir = app.outdir
    ASH_LOGGER.debug(f"app.outdir: {outdir}")

    # cfn_inc: CfnInclude = item in stack.node.children[0]
    included = [item for item in stack.node.children if isinstance(item, CfnInclude)]
    ASH_LOGGER.debug(json.dumps(included, default=str, indent=2))

    results: Dict[str, List[Result]] = {}
    cdk_nag_report_lines: Dict[str, List[cdk_nag.NagReportLine]] = {}

    # enumerate files under app.outdir ending in *-NagReport.json
    for file in Path(outdir).glob("*-NagReport.json"):
        ASH_LOGGER.debug(f"Processing NagReport file: {file}")
        nag_dict = None
        pack_name = re.sub(
            pattern=rf"-{re.escape(stack_name)}-NagReport\.json",
            repl="",
            string=file.name,
        )
        if pack_name not in cdk_nag_report_lines:
            cdk_nag_report_lines[pack_name] = []

        with open(file, "r") as f:
            nag_dict: dict = json.load(f)
        if nag_dict is None:
            ASH_LOGGER.debug(f"Could not load file as dict: {file}")
            continue
        try:
            nag_report = cdk_nag.NagReportSchema(
                **nag_dict,
            )
            cdk_nag_report_lines[pack_name].extend(nag_report.lines)
            ASH_LOGGER.debug(f"Loaded NagReport file: {file}")
            ASH_LOGGER.debug(f"Pack '{pack_name}' lines added: {len(nag_report.lines)}")
        except Exception as exc:
            ASH_LOGGER.warning(
                f"Could not parse loaded JSON dict as NagReport: {file}. Exception: {exc}"
            )

    for pack_name, report_lines in cdk_nag_report_lines.items():
        if pack_name not in results:
            results[pack_name] = []
        line: cdk_nag.NagReportLine
        for line in report_lines:
            line_dict = dict(
                rule_id=line["ruleId"],
                resource_id=line["resourceId"],
                compliance=line["compliance"],
                exception_reason=line["exceptionReason"],
                rule_level=line["ruleLevel"],
                rule_info=line["ruleInfo"],
            )
            line = cdk_nag.NagReportLine(**line_dict)
            if line.compliance == "Compliant" and not include_compliant_checks:
                ASH_LOGGER.debug(f"Skipping compliant check: {line.rule_id}")
                continue

            resource_log_id = line.resource_id.split("/")[-1]

            cfn_file_rel_path = (
                Path(template_path).absolute().relative_to(Path.cwd()).as_posix()
            )
            cfn_resource = [
                item
                for resource_id, item in model.Resources.items()
                if resource_id == resource_log_id
            ][0]
            cfn_resource_dict = {
                "Resources": {resource_log_id: cfn_resource.model_dump()}
            }
            finding = Result(
                properties=PropertyBag(
                    cdk_nag_finding=line_dict,
                    cfn_resource=cfn_resource_dict,
                    tags=[
                        "aws",
                        "cdk",
                        "cdk-nag",
                        pack_name,
                        line.rule_id,
                        resource_log_id,
                        cfn_resource.Type,
                    ],
                ),
                ruleId=line.rule_id,
                level=(
                    Level.error
                    if line.compliance == "Non-Compliant" and line.rule_level == "Error"
                    else (
                        Level.warning
                        if line.compliance == "Non-Compliant"
                        and line.rule_level != "Error"
                        else Level.note
                    )
                ),
                kind=(
                    Kind.fail
                    if line.compliance == "Non-Compliant" and line.rule_level == "Error"
                    else (
                        Kind.review
                        if line.compliance == "Suppressed"
                        and line.exception_reason != "N/A"
                        else Kind.informational
                    )
                ),
                message=Message(
                    text=f"{line.rule_info}\n\nException Reason: {line.exception_reason}"
                ),
                analysisTarget=ArtifactLocation(
                    uri=cfn_file_rel_path,
                ),
                locations=[
                    Location(
                        id=1,
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(
                                uri=line.resource_id,
                            ),
                            region=Region(
                                startLine=1,
                                endLine=1,
                                snippet=ArtifactContent(
                                    text=dump_yaml(
                                        {
                                            "Resources": {
                                                resource_log_id: cfn_resource.model_dump()
                                            }
                                        }
                                    )
                                ),
                            ),
                        ),
                    )
                ],
            )

            # finding = Result(
            #     compliance_frameworks=[pack_name],
            #     id="/".join([line.resource_id, line.rule_id]),
            #     title=line.rule_info,
            #     rule_id=line.rule_id,
            #     severity=(
            #         "CRITICAL"
            #         if line.compliance == "Non-Compliant" and line.rule_level == "Error"
            #         else (
            #             "MEDIUM"
            #             if line.compliance == "Non-Compliant"
            #             and line.rule_level != "Error"
            #             else "INFO"
            #         )
            #     ),
            #     status=(
            #         "OPEN"
            #         if line.compliance == "Non-Compliant" and line.rule_level == "Error"
            #         else (
            #             "RISK_ACCEPTED"
            #             if line.compliance == "Suppressed"
            #             and line.exception_reason != "N/A"
            #             else "INFORMATIONAL"
            #         )
            #     ),
            #     resource_name=resource_log_id,
            #     resource_type=[
            #         item.Type
            #         for resource_id, item in model.Resources.items()
            #         if resource_id == resource_log_id
            #     ][0],
            #     description=f"{line.rule_info}\n\nException Reason: {line.exception_reason}",
            #     location=Location(
            #         file_path=Path(template_path).as_posix(),
            #     ),
            #     raw=json.loads(json.dumps(line, default=str)),
            # )
            results[pack_name].append(finding)

    return CdkNagWrapperResponse(results=results, outdir=outdir, template=model)


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
        .parent.parent.parent.parent.joinpath("ash_output")
        .joinpath("scanners")
        .joinpath("cdknag"),
    )

    # jsonnable_res = {k: [item.model_dump_json() for item in v] for k, v in res.items()}
