# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The error-handling helpers on inputs that are valid but not the expected shape.

Three mechanisms, each pinned here against the behavior it replaced:

* ``safe_read_json_file`` returned any JSON value as a success, though its
  return type says ``Dict``. A results file holding a list reached
  ``parse_scanner_result_file``, whose ``data.keys()`` then raised
  AttributeError out of a progress poll.
* ``safe_write_json_file`` opened and truncated the target before serializing,
  so a value json could not encode left the previous file gone and a partial
  document in its place.
* ``create_error_response`` rebuilt tuples in the error's context with
  ``type(value)(generator)``, which a namedtuple's constructor refuses, and
  recursed without end on a context that referred to itself, so the error
  handler itself raised.
"""

import json
from typing import NamedTuple

import pytest

from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
    safe_read_json_file,
    safe_write_json_file,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_tracking import (
    parse_scanner_result_file,
)
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

pytestmark = pytest.mark.unit


class TestSafeReadJsonFileReturnsObjectsOnly:
    @pytest.mark.parametrize(
        "text,found", [("[1, 2]", "list"), ('"results"', "str"), ("7", "int")]
    )
    def test_a_non_object_document_is_a_format_error(self, tmp_path, text, found):
        path = tmp_path / "results.json"
        path.write_text(text, encoding="utf-8")

        data, error = safe_read_json_file(path)

        assert data is None
        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_FORMAT.value
        assert error.context["found_type"] == found
        assert "JSON object" in str(error)
        assert str(path) in str(error)

    def test_an_object_document_is_returned(self, tmp_path):
        path = tmp_path / "results.json"
        path.write_text('{"status": "PASSED"}', encoding="utf-8")

        data, error = safe_read_json_file(path)

        assert error is None
        assert data == {"status": "PASSED"}

    def test_the_progress_caller_gets_no_findings_instead_of_an_exception(
        self, tmp_path
    ):
        path = tmp_path / "ASH.ScanResults.json"
        path.write_text('["not", "an", "object"]', encoding="utf-8")

        assert parse_scanner_result_file(path) == []


class TestSafeWriteJsonFileKeepsThePreviousContent:
    def test_an_unserializable_value_leaves_the_file_as_it_was(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text('{"kept": true}', encoding="utf-8")

        error = safe_write_json_file(path, {"bad": object()})

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_FORMAT.value
        assert json.loads(path.read_text(encoding="utf-8")) == {"kept": True}
        # No staging file or other leftover beside the kept file.
        assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]

    def test_a_self_referencing_value_is_refused_without_a_write(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text('{"kept": true}', encoding="utf-8")
        loop = {}
        loop["self"] = loop

        error = safe_write_json_file(path, loop)

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_FORMAT.value
        assert json.loads(path.read_text(encoding="utf-8")) == {"kept": True}
        assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]

    def test_a_serializable_value_is_written(self, tmp_path):
        path = tmp_path / "state.json"

        assert safe_write_json_file(path, {"a": [1, 2]}) is None
        assert json.loads(path.read_text(encoding="utf-8")) == {"a": [1, 2]}
        assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


class TestSafeWriteJsonFileBlamesThePathForAPathError:
    def test_a_path_the_system_refuses_is_an_invalid_path_not_bad_data(self, tmp_path):
        """The open raises ValueError for an embedded NUL, as json.dumps does for
        a self-referencing value; caught together, the path error read as
        "Invalid data format for JSON serialization" with invalid_format."""
        path = tmp_path / "sta\x00te.json"

        error = safe_write_json_file(path, {"a": 1})

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert "Invalid data format" not in str(error)
        assert "not valid" in str(error)
        assert list(tmp_path.iterdir()) == []

    def test_the_control_a_serializable_value_still_writes(self, tmp_path):
        path = tmp_path / "state.json"

        assert safe_write_json_file(path, {"a": 1}) is None
        assert json.loads(path.read_text(encoding="utf-8")) == {"a": 1}


class Pair(NamedTuple):
    left: str
    right: int


class TestCreateErrorResponseSurvivesItsContext:
    def test_a_namedtuple_in_the_context_is_kept_as_one(self):
        error = MCPResourceError("x", context={"pair": Pair("a\nb", 2)})

        response = create_error_response(error, "op")

        shown = response["context"]["pair"]
        assert isinstance(shown, Pair)
        assert shown.left == raw_controls_on_one_line("a\nb")
        assert "\n" not in shown.left
        assert shown.right == 2

    def test_a_self_referencing_context_is_cut_not_recursed(self):
        context = {"name": "scan\x1b[0m"}
        context["again"] = context
        error = MCPResourceError("x", context=context)

        response = create_error_response(error, "op")

        shown = response["context"]
        assert shown["name"] == raw_controls_on_one_line("scan\x1b[0m")
        assert "\x1b" not in shown["name"]
        assert shown["again"] == "<recursive>"

    def test_a_list_that_contains_itself_is_cut(self):
        """The cycle guard tracks every container it is inside, not dicts only:
        a guard keyed on dict ids would recurse without end here."""
        loop: list = ["x\x1b[0m"]
        loop.append(loop)
        error = MCPResourceError("x", context={"loop": loop})

        response = create_error_response(error, "op")

        shown = response["context"]["loop"]
        assert shown[0] == raw_controls_on_one_line("x\x1b[0m")
        assert shown[1] == "<recursive>"

    def test_a_cycle_through_a_tuple_is_cut(self):
        loop: list = []
        loop.append((loop, "y\tz"))
        error = MCPResourceError("x", context={"loop": loop})

        response = create_error_response(error, "op")

        assert response["context"]["loop"] == [
            ("<recursive>", raw_controls_on_one_line("y\tz"))
        ]

    def test_a_value_seen_twice_on_different_branches_is_shown_twice(self):
        """Only a cycle is cut; the same list under two keys is not one."""
        shared = ["a\tb"]
        error = MCPResourceError("x", context={"one": shared, "two": shared})

        response = create_error_response(error, "op")

        expected = [raw_controls_on_one_line("a\tb")]
        assert response["context"]["one"] == expected
        assert response["context"]["two"] == expected
