"""The template model keeps logical ids as text and reads JSON with the JSON parser.

Three gaps in ``utils/cfn_template_model.py`` pinned here:

* the YAML loader kept YAML 1.1's int, bool and null resolvers for mapping keys, so
  a valid alphanumeric logical id such as ``2024``, ``On`` or ``No`` became a
  non-string key, failed the model's ``Dict[str, ...]`` and counted the whole
  template as a failed target; a plain key is text now;
* a JSON template was read as YAML first, which decodes a ``\\uD83D\\uDE00`` escape
  pair as two lone surrogates where JSON means one character; a text that opens
  with ``{`` is read by the JSON parser first now;
* the candidate suffixes were matched case-sensitively and left out ``.template``,
  so ``Stack.YAML`` and ``stack.template`` were never handed to any scanner.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.cfn_template_model import (
    CFN_CANDIDATE_SUFFIXES,
    active_global_ignore_paths,
    cloudformation_candidate_files,
    get_model_from_template_text,
    is_template_candidate,
)

pytestmark = pytest.mark.unit

TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"


def test_numeric_boolean_and_null_logical_ids_stay_text():
    text = (
        "Resources:\n"
        "  2024:\n    Type: AWS::S3::Bucket\n"
        "  On:\n    Type: AWS::S3::Bucket\n"
        "  No:\n    Type: AWS::S3::Bucket\n"
        "  Null:\n    Type: AWS::S3::Bucket\n"
        "  1.5:\n    Type: AWS::S3::Bucket\n"
    )
    model = get_model_from_template_text(text, "ids.yaml")
    assert model is not None
    assert sorted(model.Resources) == ["1.5", "2024", "No", "Null", "On"]


def test_values_keep_their_yaml_types():
    text = (
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      Count: 3\n"
    )
    model = get_model_from_template_text(text, "values.yaml")
    assert model is not None
    assert model.Resources["B"].model_extra["Properties"]["Count"] == 3


def test_a_json_surrogate_pair_is_one_character():
    text = (
        '{"Resources": {"B": {"Type": "AWS::S3::Bucket", '
        '"Properties": {"BucketName": "\\ud83d\\ude00"}}}}'
    )
    model = get_model_from_template_text(text, "emoji.json")
    assert model is not None
    name = model.Resources["B"].model_extra["Properties"]["BucketName"]
    assert name == "😀"
    assert len(name) == 1


def test_json_with_a_byte_order_mark_and_tabs_is_read():
    text = '\ufeff{\n\t"Resources": {\n\t\t"Q": {"Type": "AWS::SQS::Queue"}\n\t}\n}'
    model = get_model_from_template_text(text, "bom.json")
    assert model is not None and list(model.Resources) == ["Q"]


def test_text_that_opens_a_brace_but_is_not_json_still_parses_as_yaml():
    # Flow-style YAML with an unquoted key is not JSON; YAML reads it.
    text = "{Resources: {Q: {Type: AWS::SQS::Queue}}}"
    model = get_model_from_template_text(text, "flow.yaml")
    assert model is not None and list(model.Resources) == ["Q"]


def test_candidate_suffixes_match_any_case_and_include_template():
    assert ".template" in CFN_CANDIDATE_SUFFIXES
    assert is_template_candidate("Stack.YAML")
    assert is_template_candidate("stack.JSON")
    assert is_template_candidate(Path("deep") / "stack.template")
    assert not is_template_candidate("notes.txt")
    assert not is_template_candidate("template")


def test_cloudformation_candidate_files_selects_upper_case_and_template_names(
    ash_temp_path,
):
    source = ash_temp_path / "src"
    source.mkdir()
    for name in ("Stack.YAML", "stack.template", "notes.txt"):
        (source / name).write_text(TEMPLATE, encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=get_default_config(),
    )
    found = cloudformation_candidate_files(context, "source")
    assert sorted(Path(p).name for p in found) == ["Stack.YAML", "stack.template"]


def test_global_ignore_paths_are_none_under_ignore_suppressions(ash_temp_path):
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="ignored/", reason="generated")
    ]
    source = ash_temp_path / "src"
    source.mkdir()
    honored = PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=config,
    )
    assert [e.path for e in active_global_ignore_paths(honored)] == ["ignored/"]
    ignoring = PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=config,
        ignore_suppressions=True,
    )
    assert active_global_ignore_paths(ignoring) == []
