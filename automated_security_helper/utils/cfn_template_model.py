from cfn_tools import load_yaml
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field


from typing import Annotated, Dict


class CloudFormationResource(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        validate_default=True,
    )

    Type: Annotated[str, Field(pattern=r"^([a-zA-Z0-9:]+)$")]


class CloudFormationTemplateModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        validate_default=True,
    )

    Resources: Dict[str, CloudFormationResource]


def get_model_from_template(
    template_path: Path | None = None,
) -> CloudFormationTemplateModel | None:
    if template_path is None:
        return None

    # Reading and parsing sit inside the try alongside the validation, because all three
    # answer one question -- is there a CloudFormation template at this path -- and None
    # is this function's only way to say no. `load_yaml` used to run above the try, so a
    # file cfn_tools cannot parse raised instead of being skipped: a tsconfig.json with
    # // comments raises ParserError, a mkdocs.yml carrying a !!python/name: tag raises
    # ConstructorError. Callers scan whatever a repository happens to contain, so those
    # are ordinary inputs rather than edge cases.
    #
    # The read is inside too, not just the parse. A file that is not valid UTF-8 fails at
    # f.read() and would otherwise escape by the same route the parse error did, which
    # would fix one instance of this and leave the class.
    try:
        with open(template_path, mode="r", encoding="utf-8") as f:
            template = load_yaml(f.read())
        res = CloudFormationTemplateModel.model_validate(template)
    except Exception:
        return None
    return res
