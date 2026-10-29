"""Limits of the template loaders: merge-key growth, a BOM before JSON, SKIPPED vs MISSING.

Three behaviors of ``utils/cfn_template_model.py`` pinned here:

* A YAML merge key (``<<``) that doubles a mapping at every link of an anchor chain
  grows the flattened pair list exponentially (thirty links are a billion pairs
  from a 1 KB file), in the unsandboxed ASH process. The loaders refuse a merge that
  grows a mapping past ``MERGED_MAPPING_PAIRS_BOUND``.
* A JSON template with a UTF-8 BOM and tab indentation was never modeled: YAML
  refused the tabs and ``json.loads`` refused the BOM.
* ``holds_cloudformation_template`` counts a template the scanners report as a
  failed, unevaluated target (its structure is a template and a value could not be
  built), so a tool-absent run reads MISSING where the tool-present run reports a
  failed target, not SKIPPED.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils import cfn_template_model
from automated_security_helper.utils.cfn_template_model import (
    TemplateConstructorError,
    _could_be_a_template,
    get_model_from_template_text,
    holds_cloudformation_template,
    unevaluable_template_reason,
)

pytestmark = pytest.mark.unit

BOM = chr(0xFEFF)


def _doubling_merge_chain(links: int) -> str:
    """``a1`` merges ``a0`` twice, ``a2`` merges ``a1`` twice, and so on."""
    lines = ["a0: &a0 {k: v}"]
    for index in range(1, links + 1):
        lines.append(f"a{index}: &a{index} {{<<: [*a{index - 1}, *a{index - 1}]}}")
    lines.append(f"Resources: *a{links}")
    return "\n".join(lines) + "\n"


def test_a_doubling_merge_chain_is_refused_as_a_constructor_error():
    """At the base this read ran to a billion pairs (2**30) before anything else."""
    with pytest.raises(TemplateConstructorError):
        get_model_from_template_text(_doubling_merge_chain(30), "chain.yaml")


def test_the_lenient_read_refuses_the_same_chain():
    """``_could_be_a_template`` reads with the SafeLoader-based loader, bounded too."""
    assert isinstance(_could_be_a_template(_doubling_merge_chain(30)), bool)


def test_a_merge_within_the_bound_is_still_merged():
    text = (
        "Defaults: &defaults\n"
        "  Type: AWS::S3::Bucket\n"
        "Resources:\n"
        "  B:\n"
        "    <<: *defaults\n"
        "    Properties:\n"
        "      BucketName: b\n"
    )
    model = get_model_from_template_text(text, "merged.yaml")
    assert model is not None
    assert model.Resources["B"].Type == "AWS::S3::Bucket"
    # Read through the module so a base without the bound fails this test alone
    # instead of failing the whole file's collection.
    assert cfn_template_model.MERGED_MAPPING_PAIRS_BOUND >= 10_000


def test_a_bom_json_template_indented_with_tabs_is_modeled():
    text = BOM + '{\n\t"Resources": {\n\t\t"B": {"Type": "AWS::S3::Bucket"}\n\t}\n}\n'
    model = get_model_from_template_text(text, "bom.json")
    assert model is not None
    assert model.Resources["B"].Type == "AWS::S3::Bucket"


def test_a_bom_json_file_with_tabs_counts_in_the_lenient_read():
    """No CloudFormation marker in the text, so the answer has to come from JSON."""
    text = BOM + '{\n\t"Resources": {"X": {"Type": "Custom::Thing"}}\n}\n'
    assert _could_be_a_template(text) is True


def test_a_failed_target_counts_as_a_template_for_the_tool_absent_check(tmp_path):
    """The scanners count this file as failed; the MISSING/SKIPPED check must too.

    Its structure is a template, a value in it cannot be built, and its text
    carries no ``AWS::`` marker, so at the base the lenient read answered False.
    """
    text = (
        "Resources:\n"
        "  X:\n"
        "    Type: Custom::Thing\n"
        "    Properties:\n"
        "      Count: !!int forty-two\n"
    )
    candidate = tmp_path / "custom.yaml"
    candidate.write_text(text, encoding="utf-8")
    assert unevaluable_template_reason(candidate, tmp_path) is not None
    assert _could_be_a_template(text) is False
    assert holds_cloudformation_template([candidate], tmp_path) is True
