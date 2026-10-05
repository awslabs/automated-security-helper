from collections.abc import Mapping

from cfn_tools import load_yaml
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field


from typing import Annotated, Dict

from automated_security_helper.utils.log import ASH_LOGGER


class CloudFormationTemplateModelError(Exception):
    """A document that is CloudFormation but that this model cannot represent.

    This exists to separate two answers that used to share one ``None`` return, and the
    conflation was a false negative rather than a cosmetic problem. Both consumers --
    ``cfn_nag_scanner`` and ``cdk_nag_wrapper`` -- read ``None`` as "this file is not a
    CloudFormation template", which is an expected skip that increments no target
    counter. A real template rejected by this model inherited that treatment, so a scan
    set in which every template tripped the model ended with ``targets_attempted`` at
    zero, which ``ScanResultsContainer.determine_status`` reports as SKIPPED with exit
    code 0. Nothing above TRACE was emitted anywhere along that path.

    The distinction drawn here is "does the loaded document carry a ``Resources``
    mapping". If it does not, the file is not CloudFormation and ``None`` is correct. If
    it does, failing to model it is a limitation of this model, and the consumer must
    count a failed target so the run cannot read as clean. The false-positive direction
    -- some non-template file that happens to carry a ``Resources`` mapping now counts
    as a failed target and logs a warning -- is the safe direction: it is visible and
    fixable, where the previous behavior was neither.
    """

    def __init__(self, template_path: Path | str, error: Exception):
        self.template_path = template_path
        self.error = error
        super().__init__(f"{template_path}: {type(error).__name__}: {error}")


class CloudFormationResource(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,
        validate_default=True,
    )

    # The charset CloudFormation documents, not a narrower guess. The AWS CloudFormation
    # User Guide's "Specifying custom resource type names" section states that a custom
    # resource type name may contain alphanumeric characters and the characters _@-, so
    # the previous ^([a-zA-Z0-9:]+)$ rejected type names AWS explicitly permits --
    # `Custom::Ash-Image-Bootstrap`, `Custom::DB_Migrator`, `Custom::My@Thing`. Because
    # `Resources` is a Dict of these, one such resource failed the whole template, and
    # the whole template was then classified as not-CloudFormation and never scanned.
    #
    # The trailing hyphen inside the class is a literal hyphen; it has to stay last.
    Type: Annotated[str, Field(pattern=r"^[a-zA-Z0-9:_@-]+$")]


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
    """Model *template_path* as CloudFormation, or say which kind of no it is.

    Returns ``None`` only when the file is not CloudFormation: no path was given, or the
    loaded document carries no ``Resources`` mapping. Raises
    :class:`CloudFormationTemplateModelError` when the document does carry one but this
    model rejects it, so the caller can count a failed target instead of an unscanned
    skip. Exceptions from ``load_yaml`` propagate unchanged -- a file that is not
    parseable YAML or JSON never reached this model in the first place, and the two
    callers already classify that case for themselves.
    """
    if template_path is None:
        return None

    with open(template_path, mode="r", encoding="utf-8") as f:
        template = load_yaml(f.read())

    # The one question that separates "not CloudFormation" from "CloudFormation this
    # model cannot represent". `cfn_tools.load_yaml` returns an ODict, which is a dict
    # and therefore a Mapping, so this admits every real template; a `Resources: {}`
    # template stays admitted, as it was before.
    if not isinstance(template, Mapping) or not isinstance(
        template.get("Resources"), Mapping
    ):
        return None

    try:
        return CloudFormationTemplateModel.model_validate(template)
    except Exception as e:
        # Restored from two commented-out debug lines. At WARNING because a template ASH
        # cannot model is a coverage hole rather than noise, and because DEBUG is below
        # the default level -- with the lines commented out this function emitted nothing
        # at any verbosity, so the only record of an unscanned template was a consumer's
        # TRACE line claiming the file was not CloudFormation.
        ASH_LOGGER.warning(
            f"Template {template_path} carries a Resources mapping but could not be "
            f"modeled as CloudFormation, so no rule will be evaluated against it: "
            f"{type(e).__name__}: {e}"
        )
        raise CloudFormationTemplateModelError(template_path, e) from e
