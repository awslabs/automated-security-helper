"""A SafeLoader constructor error never escapes the lenient template read.

``_could_be_a_template`` is asked by ``holds_cloudformation_template`` from inside
the arm that passes over a file the template parser rejected, and cfn-nag's and
cdk-nag's ``scan()`` ask that from inside their own parse-failure handlers. It
re-reads the text with a ``SafeLoader``, whose explicit-tag constructors raise
``KeyError`` (``!!bool maybe``), ``AttributeError`` (``!!timestamp nonsense``) and
``IndexError`` (``!!float ""``) besides the ``ValueError`` of ``!!int forty-two``.
Only the last was caught, so the others escaped and ended the whole scan, the
good templates beside the file included.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils.cfn_template_model import (
    _could_be_a_template,
    holds_cloudformation_template,
)

pytestmark = pytest.mark.unit

TEMPLATE_WITH_BAD_VALUE = (
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
    "    Properties:\n"
    "      Flag: {value}\n"
)

NOT_A_TEMPLATE_WITH_BAD_VALUE = "service:\n  name: web\n  flag: {value}\n"

CONSTRUCTOR_FAILURES = [
    pytest.param("!!bool maybe", id="bool-KeyError"),
    pytest.param("!!timestamp nonsense", id="timestamp-AttributeError"),
    pytest.param('!!float ""', id="float-IndexError"),
    pytest.param("!!int forty-two", id="int-ValueError"),
]


@pytest.mark.parametrize("value", CONSTRUCTOR_FAILURES)
def test_a_template_with_an_unbuildable_tagged_value_is_still_a_template(value):
    """The answer comes from the text's CloudFormation marker, not an exception."""
    text = TEMPLATE_WITH_BAD_VALUE.format(value=value)
    assert _could_be_a_template(text) is True


@pytest.mark.parametrize("value", CONSTRUCTOR_FAILURES)
def test_a_non_template_with_an_unbuildable_tagged_value_is_not_one(value):
    text = NOT_A_TEMPLATE_WITH_BAD_VALUE.format(value=value)
    assert _could_be_a_template(text) is False


@pytest.mark.parametrize("value", CONSTRUCTOR_FAILURES)
def test_holds_cloudformation_template_answers_instead_of_raising(tmp_path, value):
    """At the base ``!!bool maybe`` raised KeyError out of this call."""
    candidate = tmp_path / "stack.yaml"
    candidate.write_text(TEMPLATE_WITH_BAD_VALUE.format(value=value), encoding="utf-8")
    assert holds_cloudformation_template([candidate], tmp_path) is True


def test_a_good_template_beside_a_bad_one_still_counts(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(TEMPLATE_WITH_BAD_VALUE.format(value="!!bool maybe"), "utf-8")
    good = tmp_path / "good.yaml"
    good.write_text("Resources:\n  Q:\n    Type: AWS::SQS::Queue\n", "utf-8")
    assert holds_cloudformation_template([bad, good], tmp_path) is True
