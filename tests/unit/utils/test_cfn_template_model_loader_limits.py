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

import os
from unittest.mock import patch

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


def _chain_in_a_sequence(links: int, merges: int) -> str:
    """The doubling chain to ``a<links>`` anchored INSIDE a sequence, then ``c0``
    merging ``a<links>`` once and ``c1..c<merges>`` each merging the one before, and
    a ``Resources`` that merges the last.

    A mapping inside a sequence is constructed later than the mapping that merges
    it (PyYAML builds sequences through a deferred generator), so every mapping of
    the chain is flattened inside the ``Resources`` pre-check, nested, and the
    document's sum has to survive that nesting.
    """
    lines = ["Defaults:", "  - &a0 {k: v}"]
    for index in range(1, links + 1):
        lines.append(f"  - &a{index} {{<<: [*a{index - 1}, *a{index - 1}]}}")
    lines.append(f"  - &c0 {{<<: *a{links}}}")
    for index in range(1, merges + 1):
        lines.append(f"  - &c{index} {{<<: *c{index - 1}}}")
    lines.append(f"Resources: {{<<: *c{merges}}}")
    return "\n".join(lines) + "\n"


def test_a_doubling_chain_anchored_inside_a_sequence_is_refused_by_both_loaders():
    """At the previous tip the document's sum was read once, before the merged
    mappings were flattened, and written back after them: a mapping flattened
    inside that call added its own merges to the sum first, and the write erased
    them. So a chain whose anchors sit inside a list (every one flattened inside
    the ``Resources`` pre-check) read a sum of zero at every level and was never
    refused, although ``a1..a16`` alone add 131,070 pairs; three more mappings
    each merging ``a16`` then allocated 65,536 pair references apiece under a
    document-wide bound of 100,000. Top-level anchors never reached this: cfn_tools
    builds top-level mappings eagerly, so each was flattened before the mapping
    that merges it."""
    text = _chain_in_a_sequence(16, 3)
    with pytest.raises(yaml.constructor.ConstructorError) as refused:
        yaml.load(text, Loader=cfn_template_model._TemplateLoader)  # nosec B506
    assert "added by this document's merges" in str(refused.value), str(refused.value)
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.load(text, Loader=cfn_template_model._TagTolerantLoader)  # nosec B506
    with pytest.raises(TemplateConstructorError):
        get_model_from_template_text(text, "nested-chain.yaml")
    # The lenient read answers the question it is asked and raises nothing.
    assert isinstance(_could_be_a_template(text), bool)


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


def _base_flatten_calls(text: str) -> tuple[int, Exception | None]:
    """How many times PyYAML's own ``flatten_mapping`` ran while loading ``text``.

    The pre-check wraps it, so this counts the copies and scans the base class
    made, not the pre-check's own calls. Patched on the SafeConstructor method the
    template loader inherits (``super().flatten_mapping`` resolves to it).
    """
    calls = 0
    original = yaml.constructor.SafeConstructor.flatten_mapping

    def counting(self, node):
        nonlocal calls
        calls += 1
        return original(self, node)

    with patch.object(yaml.constructor.SafeConstructor, "flatten_mapping", counting):
        try:
            yaml.load(text, Loader=cfn_template_model._TemplateLoader)  # nosec B506
        except yaml.constructor.ConstructorError as refused:
            return calls, refused
    return calls, None


def test_a_mapping_merged_several_times_is_flattened_once():
    """At the previous tip ``{<<: [*a, *a, *a]}`` ran the base flatten over ``a``
    once per alias in the pre-check and once more per alias in the base class's
    own loop: nine runs for three mappings (the document root, ``a`` and ``b``).
    Flattened nodes are now remembered on the loader, so each runs once."""
    calls, refused = _base_flatten_calls("a: &a {k: v}\nb: {<<: [*a, *a, *a]}\n")
    assert refused is None
    assert calls == 3, calls


def test_a_wide_merge_past_the_bound_is_refused_at_the_first_alias_that_passes_it():
    """``{<<: [*a15 x 400]}``: a15 holds 32,768 pairs, and the chain a1..a15 has
    already added 65,534 to the document's sum, so the second alias passes the
    100,000 bound (65,534 + 2 x 32,768 = 131,070). At the previous tip every one of
    the 400 aliases flattened a15 again (about 65,000 Python steps each) before the
    bound was compared; now a15 is flattened once and the refusal comes at the
    second alias, which the sum named in the error pins."""
    aliases = ", ".join(["*a15"] * 400)
    text = _chain_then(15, f"x: {{<<: [{aliases}]}}\nResources: {{}}\n")
    calls, refused = _base_flatten_calls(text)
    assert refused is not None and "would expand this mapping" in str(refused)
    assert "(131070 added by this document's merges)" in str(refused), str(refused)
    # The document root and the chain's 16 mappings, each flattened once by the
    # base class; the wide merge adds no run of its own before it is refused.
    assert calls == 17, calls


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


def test_a_candidate_that_is_not_utf8_counts_only_when_its_text_is_a_template(
    tmp_path,
):
    """At the previous tip any candidate whose UTF-8 read failed counted as a
    template (MISSING with the tool absent), matching the scanners, which failed it
    with the tool present. Both now judge the text, decoded as well as it can be:
    a Latin-1 file with no CloudFormation in it is not a template, a Latin-1 file
    with a Resources mapping is, and a UTF-16 template (decoded by its byte-order
    mark) is."""
    notes = tmp_path / "latin-notes.yaml"
    notes.write_bytes(b"greeting: caf\xe9\n")
    stack = tmp_path / "latin-stack.yaml"
    stack.write_bytes(b"Resources:\n  caf\xe9: {}\n")
    utf16 = tmp_path / "utf16.json"
    utf16.write_bytes(
        '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-16")
    )
    # No byte-order mark: found only by the reading as UTF-16 (or UTF-32).
    nomark = tmp_path / "utf16-nomark.json"
    nomark.write_bytes(
        '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-16-be")
    )
    nomark32 = tmp_path / "utf32-nomark.json"
    nomark32.write_bytes(
        '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-32-le")
    )
    assert holds_cloudformation_template([notes], tmp_path) is False
    assert holds_cloudformation_template([stack], tmp_path) is True
    assert holds_cloudformation_template([utf16], tmp_path) is True
    assert holds_cloudformation_template([nomark], tmp_path) is True
    assert holds_cloudformation_template([nomark32], tmp_path) is True
    assert holds_cloudformation_template([notes, utf16], tmp_path) is True


@pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links")
def test_a_hard_linked_non_utf8_candidate_is_judged_like_its_twin(tmp_path):
    """The first read admits a hard-linked regular file; at the previous tip the
    second read refused it (TreeInputRefused, caught here as "every doubt counts as a
    template"), so the hard link counted as a template where its twin did not."""
    notes = tmp_path / "latin-notes.yaml"
    notes.write_bytes(b"greeting: caf\xe9\n")
    linked = tmp_path / "linked-notes.yaml"
    os.link(notes, linked)
    assert holds_cloudformation_template([linked], tmp_path) is False
    assert holds_cloudformation_template([notes, linked], tmp_path) is False


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
