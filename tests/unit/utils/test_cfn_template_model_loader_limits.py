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
import yaml

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


def _chain_then(links: int, tail: str) -> str:
    """The doubling chain to ``a<links>`` (each link under the bound), then ``tail``."""
    lines = ["a0: &a0 {k: v}"]
    for index in range(1, links + 1):
        lines.append(f"a{index}: &a{index} {{<<: [*a{index - 1}, *a{index - 1}]}}")
    return "\n".join(lines) + "\n" + tail


def test_siblings_that_each_merge_a_large_mapping_once_are_refused_together():
    """At the base each sibling was under the bound on its own (16,384 pairs), so
    five of them were all built on top of the chain's 32,766; the document's
    merges are now summed and the fifth sibling is refused."""
    text = _chain_then(
        14,
        "v: {<<: *a14}\nw: {<<: *a14}\nx: {<<: *a14}\ny: {<<: *a14}\nz: {<<: *a14}\n"
        "Resources: {}\n",
    )
    with pytest.raises(TemplateConstructorError):
        get_model_from_template_text(text, "siblings.yaml")


def test_a_wide_merge_is_refused_before_its_list_is_built():
    """``{<<: [*a10 x 200]}`` is 204,800 pairs. The loader's own error names the
    expansion the merge WOULD have built: the pre-check computes it from the merged
    mappings' sizes and refuses before any list is allocated (at the base the
    message named the size of a list already built)."""
    aliases = ", ".join(["*a10"] * 200)
    text = _chain_then(10, f"x: {{<<: [{aliases}]}}\nResources: {{}}\n")
    with pytest.raises(yaml.constructor.ConstructorError) as raised:
        yaml.load(text, Loader=cfn_template_model._TemplateLoader)  # nosec B506
    assert "would expand this mapping" in str(raised.value), str(raised.value)
    with pytest.raises(TemplateConstructorError):
        get_model_from_template_text(text, "wide.yaml")


def test_a_mapping_that_merges_itself_builds_empty_as_pyyaml_does():
    """``a: &a {<<: *a}``: PyYAML deletes the merge key before it recurses and builds
    ``{}``. At the previous tip the pre-check flattened the merged node while the
    key was still there and recursed into the same node until RecursionError,
    which the model then reported as "nested past the YAML loader's recursion
    limit" for a one-line file."""
    loaded = yaml.load("a: &a {<<: *a}\n", Loader=cfn_template_model._TemplateLoader)  # nosec B506
    assert loaded == {"a": {}}
    text = "Defaults: &d {<<: *d}\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"
    model = get_model_from_template_text(text, "self-merge.yaml")
    assert model is not None
    assert model.Resources["B"].Type == "AWS::S3::Bucket"


def test_a_merge_well_within_the_bound_across_the_document_is_still_merged():
    text = _chain_then(
        8,
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: {<<: *a8}\n",
    )
    model = get_model_from_template_text(text, "within.yaml")
    assert model is not None


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
