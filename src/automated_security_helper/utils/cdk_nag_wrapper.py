#!/usr/bin/env python3
import inspect
import os
import re
import shutil

from pydantic import BaseModel, ConfigDict, Field
from cfn_tools import load_yaml

from automated_security_helper.models.core import Location
from automated_security_helper.models.iac_scan import IaCVulnerability

# noqa
os.environ["JSII_SILENCE_WARNING_DEPRECATED_NODE_VERSION"] = "1"

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
from aws_cdk.assertions import (
    Match,
    Annotations,
)
from aws_cdk.cloudformation_include import (
    CfnInclude,
)
from aws_cdk.cx_api import (
    SynthesisMessage,
    SynthesisMessageLevel,
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

    return CloudFormationTemplateModel.model_validate(template)


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
) -> Dict[str, List[IaCVulnerability]] | None:
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
    # nag_pack_lookup = {
    #     "AwsSolutionsChecks": {
    #         "pack": cdk_nag.AwsSolutionsChecks(),
    #         "packName": "AwsSolutions",
    #     },
    #     "HIPAASecurityChecks": {
    #         "pack": cdk_nag.HIPAASecurityChecks(),
    #         "packName": "HIPAA.Security",
    #     },
    #     "NIST80053R4Checks": {
    #         "pack": cdk_nag.NIST80053R4Checks(),
    #         "packName": "NIST.800.53.R4",
    #     },
    #     "NIST80053R5Checks": {
    #         "pack": cdk_nag.NIST80053R5Checks(),
    #         "packName": "NIST.800.53.R5",
    #     },
    #     "PCIDSS321Checks": {
    #         "pack": cdk_nag.PCIDSS321Checks(),
    #         "packName": "PCI.DSS.321",
    #     },
    # }
    stack = WrapperStack(
        app,
        "ASHCDKNagScanner",
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
    ASH_LOGGER.debug(f"outdir: {outdir}")

    # cfn_inc: CfnInclude = item in stack.node.children[0]
    included = [item for item in stack.node.children if isinstance(item, CfnInclude)]
    ASH_LOGGER.debug(json.dumps(included, default=str, indent=2))

    results: Dict[str, List[IaCVulnerability]] = {}

    item: SynthesisMessage
    for pack in nag_packs:
        results[pack] = []
        pack_type: type[cdk_nag.NagPack] = nag_pack_lookup[pack]["packType"]
        pack_name = pack_type().read_pack_name
        ASH_LOGGER.debug(f"\n===  Pack '{pack_name}' Annotations  ===")
        cdk_nag_annotations = [
            *(
                Annotations.from_stack(stack).find_info(
                    "*",
                    Match.string_like_regexp(rf"{re.escape(pack_name)}-.*"),
                )
            ),
            *(
                Annotations.from_stack(stack).find_warning(
                    "*",
                    Match.string_like_regexp(rf"{re.escape(pack_name)}-.*"),
                )
            ),
            *(
                Annotations.from_stack(stack).find_error(
                    "*",
                    Match.string_like_regexp(rf"{re.escape(pack_name)}-.*"),
                )
            ),
        ]
        ASH_LOGGER.debug(f"Pack '{pack}' annotations: {len(cdk_nag_annotations)}")
        ASH_LOGGER.debug(
            f"Pack '{pack}' annotations: {json.dumps(cdk_nag_annotations, default=str, indent=2)}"
        )
        for item in cdk_nag_annotations:
            finding_ids: re.Match[str] | None = re.search(
                rf"({re.escape(pack_name)}-\w+):", item.entry.data
            )
            if finding_ids is not None:
                finding_id = finding_ids.group(1)

            resource_log_id = item.id.split("/")[-1]

            finding = IaCVulnerability(
                compliance_frameworks=[pack_name],
                id=f"{item.id}/{finding_id}".lstrip("/"),
                title=item.id.lstrip("/"),
                rule_id=finding_id.lstrip("/"),
                severity=(
                    "CRITICAL"
                    if item.level == SynthesisMessageLevel.ERROR
                    else (
                        "MEDIUM"
                        if item.level == SynthesisMessageLevel.WARNING
                        else "INFO"
                    )
                ),
                resource_name=resource_log_id,
                resource_type=[
                    item.Type
                    for resource_id, item in model.Resources.items()
                    if resource_id == resource_log_id
                ][0],
                description=item.entry.data,
                location=Location(
                    file_path=Path(template_path).as_posix(),
                ),
                raw=dict(
                    id=item.id,
                    level=item.level,
                    entry=json.loads(json.dumps(item.entry.__dict__, default=str)),
                ),
            )
            results[pack].append(finding)
            ASH_LOGGER.debug(f"Finding: {finding.model_dump_json(indent=2)}")

    jsonnable_res = {k: [item.model_dump() for item in v] for k, v in results.items()}

    with open(
        Path(outdir).joinpath("IaCVulnerabilities_from_Annotations.json"), "w"
    ) as f:
        json.dump(jsonnable_res, f, default=str)

    return results


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
