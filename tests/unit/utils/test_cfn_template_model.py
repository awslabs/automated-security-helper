"""Tests for cfn_template_model utilities."""

import json
import logging
import os
import sys
from types import SimpleNamespace

import pytest
import yaml

from automated_security_helper.utils import cfn_template_model
from automated_security_helper.utils.cfn_template_model import (
    CloudFormationResource,
    CloudFormationTemplateModel,
    CloudFormationTemplateModelError,
    _could_be_a_template,
    _has_top_level_resources,
    _load_template_yaml,
    _root_is_a_sequence,
    _top_level_resources_in_events,
    get_model_from_template,
    get_model_from_template_text,
    holds_cloudformation_template,
    read_template_text,
    unevaluable_template_reason,
)
from automated_security_helper.utils.scanned_tree import (
    REASON_SYMLINK,
    TreeInputRefused,
)

pytestmark = pytest.mark.unit

# Resource type names CloudFormation documents as legal and this model used to reject.
# The AWS CloudFormation User Guide's "Specifying custom resource type names" says a
# custom resource type name may contain alphanumerics and the characters _@-, so each
# of these is a template a security scanner must scan rather than classify away.
DOCUMENTED_CUSTOM_RESOURCE_TYPES = [
    "Custom::Ash-Image-Bootstrap",
    "Custom::DB_Migrator",
    "Custom::My@Thing",
]

# The AWS::LanguageExtensions Fn::ForEach shape: the value under Resources is a
# three-element list, not a resource mapping. This model cannot represent it, which is
# a limitation of the model and not a property of the file -- so it must be reported,
# not silently classified as "not CloudFormation".
FN_FOR_EACH_TEMPLATE = """Transform: AWS::LanguageExtensions
Resources:
  Fn::ForEach::Buckets:
    - Identifier
    - - A
      - B
    - 'Bucket${Identifier}':
        Type: AWS::S3::Bucket
  Keep:
    Type: AWS::S3::Bucket
"""


class TestCloudFormationResource:
    """Tests for CloudFormationResource model."""

    def test_valid_type(self):
        """A valid Type string passes validation."""
        resource = CloudFormationResource(Type="AWS::S3::Bucket")
        assert resource.Type == "AWS::S3::Bucket"

    def test_invalid_type_rejected(self):
        """A Type with invalid characters is rejected."""
        with pytest.raises(Exception):
            CloudFormationResource(Type="AWS::S3::Bucket!!")

    def test_extra_fields_allowed(self):
        """Extra fields are allowed due to ConfigDict(extra='allow')."""
        resource = CloudFormationResource(
            Type="AWS::Lambda::Function", Properties={"Handler": "index.handler"}
        )
        assert resource.Properties == {"Handler": "index.handler"}


class TestCloudFormationTemplateModel:
    """Tests for CloudFormationTemplateModel."""

    def test_valid_template(self):
        """A valid template with Resources parses correctly."""
        model = CloudFormationTemplateModel(
            Resources={"MyBucket": CloudFormationResource(Type="AWS::S3::Bucket")}
        )
        assert "MyBucket" in model.Resources
        assert model.Resources["MyBucket"].Type == "AWS::S3::Bucket"

    def test_extra_top_level_fields_allowed(self):
        """Extra top-level keys like AWSTemplateFormatVersion are allowed."""
        model = CloudFormationTemplateModel(
            AWSTemplateFormatVersion="2010-09-09",
            Resources={"Fn": CloudFormationResource(Type="AWS::Lambda::Function")},
        )
        assert model.AWSTemplateFormatVersion == "2010-09-09"


class TestGetModelFromTemplate:
    """Tests for get_model_from_template function."""

    def test_returns_none_for_none_path(self):
        """Passing None returns None."""
        assert get_model_from_template(None) is None

    def test_valid_yaml_template(self, tmp_path):
        """A valid YAML CloudFormation template is parsed into a model."""
        template_file = tmp_path / "template.yaml"  # nosec B108
        template_file.write_text("Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n")

        result = get_model_from_template(template_file)

        assert result is not None
        assert "MyBucket" in result.Resources
        assert result.Resources["MyBucket"].Type == "AWS::S3::Bucket"

    def test_document_without_resources_returns_none(self, tmp_path):
        """No Resources key means the document is not CloudFormation at all."""
        template_file = tmp_path / "bad.yaml"  # nosec B108
        # Missing Resources key entirely
        template_file.write_text("Description: no resources here\n")

        result = get_model_from_template(template_file)
        assert result is None

    def test_resources_that_is_not_a_mapping_returns_none(self, tmp_path):
        """A Resources key holding something other than a mapping is also a skip.

        The sentinel split turns on exactly one question -- is there a Resources
        mapping -- so the negative side of it needs its own case.
        """
        template_file = tmp_path / "list_resources.yaml"  # nosec B108
        template_file.write_text("Resources:\n  - not: a mapping\n")

        assert get_model_from_template(template_file) is None

    def test_invalid_resource_type_raises_rather_than_skipping(self, tmp_path):
        """A Resources mapping this model rejects is reported, not classified away.

        This assertion is the inverse of the one it replaces. Returning None here
        was the defect: both consumers read None as "not a CloudFormation file"
        and skip it without counting a target, so a scan set in which every
        template trips the model ended at zero attempts and reported SKIPPED with
        exit code 0. The file has a Resources mapping, so it is CloudFormation;
        failing to model it is this model's limitation and must be counted.
        """
        template_file = tmp_path / "bad_type.yaml"  # nosec B108
        template_file.write_text(
            "Resources:\n  Bad:\n    Type: 'invalid type with spaces'\n"
        )

        with pytest.raises(CloudFormationTemplateModelError) as excinfo:
            get_model_from_template(template_file)

        assert "bad_type.yaml" in str(excinfo.value)

    def test_rejection_is_logged_with_the_path_and_the_error(self, tmp_path, caplog):
        """The swallowed diagnostic is restored at WARNING, naming both.

        The original code had two commented-out debug lines, so the function
        emitted nothing at any verbosity and a template ASH could not model left
        no trace anywhere in the log.
        """
        template_file = tmp_path / "unmodelable.yaml"  # nosec B108
        template_file.write_text("Resources:\n  Bad:\n    Type: 'has spaces'\n")

        with caplog.at_level(logging.WARNING):
            with pytest.raises(CloudFormationTemplateModelError):
                get_model_from_template(template_file)

        messages = [record.message for record in caplog.records]
        assert any("unmodelable.yaml" in message for message in messages), messages
        assert any("ValidationError" in message for message in messages), messages
        # Named by file and error type only: the error's own text quotes the
        # rejected value out of the template, and this line reaches ash.log.
        assert not any("has spaces" in message for message in messages), messages

    @pytest.mark.parametrize("resource_type", DOCUMENTED_CUSTOM_RESOURCE_TYPES)
    def test_documented_custom_resource_charset_is_modeled(
        self, tmp_path, resource_type
    ):
        """Custom resource type names containing _, @ or - are CloudFormation.

        Each of these was rejected by the original ^([a-zA-Z0-9:]+)$ pattern, and
        the rejection was indistinguishable from "this file is not a template".
        """
        template_file = tmp_path / "custom.yaml"  # nosec B108
        template_file.write_text(
            f"Resources:\n  Thing:\n    Type: '{resource_type}'\n"
            "  Bucket:\n    Type: AWS::S3::Bucket\n"
        )

        result = get_model_from_template(template_file)

        assert result is not None
        assert result.Resources["Thing"].Type == resource_type
        assert "Bucket" in result.Resources

    def test_fn_for_each_shape_is_reported_rather_than_skipped(self, tmp_path):
        """An Fn::ForEach key under Resources is a failed target, not a skip.

        Widening the charset does not make this shape representable: the value is
        a three-element list where a resource mapping is expected. Accepting the
        document would hand a list to code downstream that expects a mapping, so
        the honest answer is to report that the template went unevaluated.
        """
        template_file = tmp_path / "for_each.yaml"  # nosec B108
        template_file.write_text(FN_FOR_EACH_TEMPLATE)

        with pytest.raises(CloudFormationTemplateModelError):
            get_model_from_template(template_file)


def _template_holding(deep: object) -> dict:
    """A template whose one resource's ``Properties.Deep`` is *deep*: 4 levels above it."""
    return {
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"Deep": deep}}
        }
    }


def _nested(kind: str, levels: int) -> object:
    """*levels* levels of lists, or of objects, the innermost empty."""
    value: object = [] if kind == "sequence" else {}
    for _ in range(levels - 1):
        value = [value] if kind == "sequence" else {"a": value}
    return value


def _decision(text: str) -> tuple:
    """What the template parser answers for *text*: the resources, or the error."""
    try:
        model = get_model_from_template_text(text, "stack.json")
    except Exception as error:
        return type(error).__name__, str(error)
    return "model", None if model is None else sorted(model.Resources)


#: A key longer than the 1,024 characters YAML allows a simple key, so YAML refuses
#: the JSON it is in for a reason other than tabs.
LONG_KEY = "k" * 2000


class TestHowDeepATemplateIsRead:
    @pytest.mark.parametrize(
        "kind,levels,expected",
        [
            pytest.param("mapping", 50, "model", id="mappings-50"),
            pytest.param("mapping", 350, "model", id="mappings-350-past-yaml"),
            pytest.param(
                "sequence", 410, "TemplateDocumentError", id="sequences-410-past-400"
            ),
        ],
    )
    def test_a_tab_indented_json_template_is_decided_as_with_spaces(
        self, kind, levels, expected
    ):
        """The same template, the same answer, whichever it is indented with.

        At the base YAML read every JSON template first and refused a tab before it
        reached the depth, so JSON decided the tab-indented form and YAML the
        space-indented one: mappings nested from about 330 levels (the YAML loader's
        limit for them) to 400 were scanned with tabs and a failed target with
        spaces, and sequences from 401 to about 490 the other way round. A text that
        opens with ``{`` is now read by the JSON parser first, so JSON_NESTING_LIMIT
        (400) decides both spellings alike: a 350-level mapping is a template and a
        410-level sequence is nested too deep, with tabs and with spaces.
        """
        document = _template_holding(_nested(kind, levels))
        tabs = json.dumps(document, indent="\t")
        spaces = json.dumps(document, indent=" ")

        assert _decision(spaces)[0] == expected, _decision(spaces)
        assert _decision(tabs) == _decision(spaces)

    @pytest.mark.parametrize(
        "levels,expected",
        [
            pytest.param(400, ("model", ["Bucket"]), id="400"),
            pytest.param(
                401,
                ("TemplateDocumentError", "it is nested past 400 levels"),
                id="401",
            ),
        ],
    )
    def test_json_yaml_refuses_for_another_reason_is_read_to_400_levels(
        self, levels, expected
    ):
        """JSON_NESTING_LIMIT: past it, json.loads's own limit would decide, which is
        994 levels on Python 3.10 and 3.11 and ten or twenty times that later on."""
        document = {LONG_KEY: 1, **_template_holding(_nested("sequence", levels - 4))}
        text = json.dumps(document)
        with pytest.raises(yaml.YAMLError):
            _load_template_yaml(text)

        assert _decision(text) == expected

    def test_a_json_read_past_the_recursion_limit_is_nested_past_400_levels(
        self, monkeypatch
    ):
        """json.loads raises RecursionError past 994 levels on Python 3.10 and 3.11;
        later versions read on, so the error is raised here for every version."""

        def too_deep(text, *args, **kwargs):
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(cfn_template_model, "json", SimpleNamespace(loads=too_deep))
        text = json.dumps({LONG_KEY: 1, **_template_holding([])})

        assert _decision(text) == (
            "TemplateDocumentError",
            "it is nested past 400 levels",
        )

    @pytest.mark.parametrize(
        "lists,counted",
        [
            pytest.param(999, False, id="1000-levels-read-to-the-end"),
            pytest.param(1000, True, id="1001-levels-stop"),
        ],
    )
    def test_the_event_read_stops_past_1000_levels(self, lists, counted):
        """Under a mapping root the structural read stops past 1,000 levels and counts
        the file; at 1,000 it reads on, here to a document with no Resources. One
        level a line, where the read is cheap: on one line it grows with about the
        square of the depth, and a hostile file 5,000 levels deep would hold each
        scanner 11 to 23.5 s."""
        text = '{"Deep":\n' + "[\n" * lists + "]\n" * lists + "}\n"

        assert _top_level_resources_in_events(text) is counted

    @pytest.mark.parametrize(
        "text,is_a_sequence",
        [
            pytest.param("[" * 100000, True, id="deep-flow-sequence"),
            pytest.param("- a\n- b\n", True, id="block-sequence"),
            pytest.param("--- !!seq\n- a\n", True, id="tagged"),
            pytest.param("[a, b]: value\n", False, id="flow-sequence-as-a-key"),
            pytest.param('{"Resources": {}}', False, id="mapping"),
            pytest.param("just text", False, id="scalar"),
            pytest.param("[\n\t1]", False, id="unreadable-before-its-first-node"),
        ],
    )
    def test_the_root_kind_is_read_from_the_first_node(self, text, is_a_sequence):
        """A sequence root is not a template, and is answered without a parse; a
        flow sequence used as a key opens a mapping, so a first character is not
        enough."""
        assert _root_is_a_sequence(text) is is_a_sequence
        if is_a_sequence:
            assert _decision(text) == ("model", None)

    def test_a_damaged_sequence_root_with_a_marker_is_no_template(self, tmp_path):
        """Each reader answers no for it, the marker in its text notwithstanding.

        It does not parse and it says ``AWSTemplateFormatVersion``, which made it a
        possibly damaged template: MISSING without the tool, and "could not parse"
        with it. Its root is a sequence, which no template has.
        """
        text = DAMAGED_SEQUENCE_ROOT
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load(text)
        assert _root_is_a_sequence(text)

        assert _could_be_a_template(text) is False
        assert _has_top_level_resources(text) is False
        assert _decision(text) == ("model", None)
        candidate = tmp_path / "stack.yaml"
        candidate.write_text(text, encoding="utf-8")
        assert holds_cloudformation_template([candidate], tmp_path) is False

    @pytest.mark.parametrize(
        "reader",
        [
            pytest.param(lambda text: _decision(text), id="the-template-parser"),
            pytest.param(_could_be_a_template, id="could-be-a-template"),
            pytest.param(_has_top_level_resources, id="the-structure-read"),
        ],
    )
    def test_a_sequence_root_is_answered_without_a_composer_parse(
        self, monkeypatch, reader
    ):
        """Each reader decides a deep sequence root at its first node. Run to the
        recursion limit first, each composer parse of it took about 1.5 s on Python
        3.10, and a decision made five."""
        import yaml.composer

        composed = []
        compose = yaml.composer.Composer.get_single_node

        def counting(loader):
            composed.append(type(loader).__name__)
            return compose(loader)

        monkeypatch.setattr(yaml.composer.Composer, "get_single_node", counting)

        reader("[" * 100000)

        assert composed == []

    def test_json_yaml_refuses_nested_past_400_levels_is_passed_over(self, tmp_path):
        """The documented limit of JSON_NESTING_LIMIT: past it such a template is
        not one ASH could not evaluate, since only a JSON read could see its
        structure, and how deep JSON reads depends on the Python version."""
        text = json.dumps(
            {LONG_KEY: 1, **_template_holding(_nested("sequence", 401 - 4))}
        )
        candidate = tmp_path / "stack.json"
        candidate.write_text(text, encoding="utf-8")
        assert _decision(text)[0] == "TemplateDocumentError"

        assert unevaluable_template_reason(candidate, tmp_path, text) is None

    @pytest.mark.parametrize("kind", ["sequence", "mapping"])
    @pytest.mark.parametrize(
        "where,levels,failed",
        [
            pytest.param("first", 1010, False, id="key-first-past-1000"),
            pytest.param("after", 990, False, id="key-after-under-1000"),
            pytest.param("after", 1010, True, id="key-after-past-1000"),
            pytest.param("inside", 1010, True, id="key-inside-past-1000"),
        ],
    )
    def test_where_yaml_meets_the_long_key_decides_past_1000_levels(
        self, tmp_path, kind, where, levels, failed
    ):
        """The exception to the documented limit: nested past EVENT_DEPTH_BOUND
        before YAML reaches the long key, the event read stops at the bound first,
        and the file counts as a failed target, as any file nested that deep does.
        Meeting the key first, or under the bound, it is passed over."""
        if where == "first":
            document = {LONG_KEY: 1, **_template_holding(_nested(kind, levels - 4))}
        elif where == "after":
            document = {**_template_holding(_nested(kind, levels - 4)), LONG_KEY: 1}
        else:
            deep = {LONG_KEY: 1}
            for _ in range(levels - 5):
                deep = [deep] if kind == "sequence" else {"a": deep}
            document = _template_holding(deep)
        # json.dumps spends one recursion level per nesting level, and the
        # documents here sit at the read's own bound, past what is left of
        # the default budget under the runner's frames on some interpreters.
        # The room is the encoder's alone; the read under test keeps its own
        # limits.
        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(limit + 4 * levels)
        try:
            text = json.dumps(document)
        finally:
            sys.setrecursionlimit(limit)
        candidate = tmp_path / "stack.json"
        candidate.write_text(text, encoding="utf-8")

        reason = unevaluable_template_reason(candidate, tmp_path, text)

        assert (reason is not None) is failed, reason


class TestReadTemplateText:
    """The template read admits a hard-linked regular file and still refuses a link.

    Both scanners read a candidate through ``read_template_text`` to decide whether
    they evaluate it. The scanned-tree rule refused a file with a second hard link,
    and both scanners took that refusal as the not-CloudFormation skip: no finding,
    no error, no failed target, so a repository that hard-links its templates was
    reported clean. A hard link to a regular file is the tree's own bytes under a
    second name and follows no link to another path, so the read admits it; a
    symlink, which does name another path, stays refused.
    """

    TEMPLATE = "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n"

    @pytest.fixture
    def tree(self, tmp_path):
        tree = tmp_path / "tree"
        tree.mkdir()
        return tree

    @pytest.fixture
    def elsewhere(self, tmp_path):
        """The template's first name, outside the scanned tree."""
        path = tmp_path / "elsewhere" / "template.yaml"
        path.parent.mkdir()
        path.write_text(self.TEMPLATE, encoding="utf-8")
        return path

    @pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links")
    def test_a_hard_linked_template_is_read_and_counted(self, tree, elsewhere):
        linked = tree / "template.yaml"
        try:
            os.link(elsewhere, linked)
        except OSError as exc:  # pragma: no cover - filesystem without hard links
            pytest.skip(f"cannot create a hard link here: {exc}")

        assert read_template_text(linked, tree) == self.TEMPLATE
        # The tool-absent check counts it, so a tree whose only template is
        # hard-linked reads MISSING without the tool, not "no template".
        assert holds_cloudformation_template([linked], tree) is True
        model = get_model_from_template(linked, scan_root=tree)
        assert model is not None
        assert "MyBucket" in model.Resources

    @pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
    def test_a_symlinked_template_is_still_refused(self, tree, elsewhere):
        """The must-not-admit control: the admit covers a hard link only."""
        (tree / "template.yaml").symlink_to(elsewhere)

        with pytest.raises(TreeInputRefused) as excinfo:
            read_template_text(tree / "template.yaml", tree)

        assert excinfo.value.reason == REASON_SYMLINK
        assert holds_cloudformation_template([tree / "template.yaml"], tree) is False


#: A template damaged so no reader parses it, whose root is a sequence: an unclosed
#: mapping after a CloudFormation marker.
DAMAGED_SEQUENCE_ROOT = (
    "- AWSTemplateFormatVersion: '2010-09-09'\n"
    "  Resources: {\n"
    "    Bucket: {Type: AWS::S3::Bucket\n"
)
