# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a python-mode dump of a finding holds for ``severity``, pinned on purpose.

Two egresses dump findings in python mode: the MCP ``diff`` tool's ``new`` and
``resolved`` lists and the CSV reporter's rows. Only the json-mode dump was
pinned, so nothing said what these two carry. They carry the ``Severity`` MEMBER:
a ``str`` subclass that compares, hashes and formats as its text, writes into csv
and json unchanged, and is refused by ``yaml.safe_dump`` (this repo's yaml writers
refuse ``str`` subclasses). A change to that is a decision, so it fails here
first.
"""

from __future__ import annotations

import pytest
import yaml

from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.models.vocab import Severity

pytestmark = pytest.mark.unit


def _finding() -> FlatVulnerability:
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="Sc",
        scanner_type="SAST",
    )


def test_the_python_dump_holds_the_member_and_the_json_dump_holds_text():
    python_dump = _finding().model_dump()
    json_dump = _finding().model_dump(mode="json")

    assert type(python_dump["severity"]) is Severity
    assert python_dump["severity"] == "HIGH"
    assert type(json_dump["severity"]) is str


def test_the_member_reads_as_its_text_where_an_egress_formats_it():
    value = _finding().model_dump()["severity"]

    assert f"{value}" == "HIGH"
    assert str(value) == "HIGH"
    assert "%s" % value == "HIGH"


def test_a_yaml_writer_refuses_the_python_dump_so_an_egress_must_not_route_one_to_it():
    with pytest.raises(yaml.representer.RepresenterError):
        yaml.safe_dump(_finding().model_dump())

    written = yaml.safe_dump(_finding().model_dump(mode="json"))
    assert yaml.safe_load(written)["severity"] == "HIGH"
