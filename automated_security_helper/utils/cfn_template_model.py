from cfn_tools import load_yaml
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field


from typing import Annotated, Any, Dict, Literal, Optional


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


def get_model_from_template(
    template_path: Path | None = None,
) -> CloudFormationTemplateModel | None:
    if template_path is None:
        return None

    with open(template_path, mode="r", encoding="utf-8") as f:
        template = load_yaml(f.read())

    try:
        res = CloudFormationTemplateModel.model_validate(template)
    except Exception:
        # ASH_LOGGER.debug(f"Error validating template: {e}")
        # ASH_LOGGER.debug(f"Error validating template: {e}")
        return None
    return res
