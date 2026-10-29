# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""suggest_suppression's ``path`` matches the finding's own file, and not another.

A suppression's ``path`` is a pattern: ``[``, ``*`` and ``?`` are glob syntax, and
a backslash is a separator (path_matching._match_form). Were suggest_suppression
to put the finding's file path there as it is, for ``x[1].py`` the suggestion
would match ``x1.py`` and not ``x[1].py``, and for a POSIX file named ``src\\app.py``
it would match ``src/app.py`` and not the file itself. The path is written as a
pattern for that one file, with ``[``, ``*`` and ``?`` as one-character classes.

A backslash has no such spelling: the dialect reads every backslash in a pattern
as a separator, a class's included. ``[!/]`` in its place would match the file,
and any other one character but ``/`` there too, so it would hide another file's
findings (``srcXapp.py``'s). A finding whose path holds a backslash is refused
instead, with ``error_type`` ``path_not_expressible``, and no suppression is
suggested.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.cli.mcp_tools import mcp_suggest_suppression
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.utils import path_matching
from automated_security_helper.utils.suppression_matcher import file_path_matches
from tests.unit.cli.mcp.test_suggest_suppression import (
    _make_aggregated_json,
    _make_vuln,
)

pytestmark = pytest.mark.unit

#: A finding's file, and a neighbor the suggestion must not cover.
CASES = {
    "a class": ("x[1].py", "x1.py"),
    "a star": ("a*b.py", "aXb.py"),
    "a question mark": ("a?.py", "ab.py"),
    "a double star": ("we**rd/x.py", "weird/x.py"),
}

#: A finding's file holding a backslash, and files a suggestion for it matched.
BACKSLASHES = {
    "one": ("src\\app.py", ("src/app.py", "srcXapp.py")),
    "two": ("a\\b\\c.py", ("a/b/c.py", "aXbYc.py")),
    "with a class": ("x[1]\\y.py", ("x[1]/y.py", "x[1]Zy.py")),
}


def _suggest(tmp_path, file_path: str) -> dict:
    vuln = _make_vuln(file_path=file_path)
    results_file = tmp_path / "ash_aggregated_results.json"
    results_file.write_text(json.dumps(_make_aggregated_json([vuln])))
    return mcp_suggest_suppression(finding_id=vuln.id, results_path=str(results_file))


def _suggested_path(tmp_path, file_path: str) -> str:
    result = _suggest(tmp_path, file_path)

    assert result["success"] is True, result
    AshSuppression(**result["json"])  # still a valid suppression
    return result["json"]["path"]


@pytest.mark.parametrize("case", sorted(BACKSLASHES))
def test_a_path_with_a_backslash_is_refused(tmp_path, case):
    file_path, others = BACKSLASHES[case]

    result = _suggest(tmp_path, file_path)

    assert result["success"] is False, result
    assert result["error_type"] == "path_not_expressible", result
    assert "json" not in result and "yaml" not in result, result
    assert file_path in result["error"], result
    for other in others:
        # The suggestion this replaced, [!/] for each backslash, matched these.
        assert not file_path_matches(other, result.get("json", {}).get("path", "")), (
            other,
            result,
        )


def test_the_refusal_is_one_line(tmp_path):
    result = _suggest(tmp_path, "src\\a\nb\x1b[2K.py")

    assert result["error_type"] == "path_not_expressible", result
    assert "\n" not in result["error"] and "\x1b" not in result["error"], result


@pytest.mark.parametrize("path", ["src\\app.py", "\\", "a/b\\"])
def test_literal_path_pattern_refuses_a_backslash(path):
    with pytest.raises(ValueError) as raised:
        path_matching.literal_path_pattern(path)

    assert type(raised.value).__name__ == "PathNotExpressible", raised.value


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_suggestion_covers_the_file_and_not_its_neighbor(tmp_path, case):
    file_path, neighbor = CASES[case]

    path = _suggested_path(tmp_path, file_path)

    assert file_path_matches(file_path, path), (file_path, path)
    assert not file_path_matches(neighbor, path), (neighbor, path)


def test_control_a_plain_path_is_suggested_as_it_is(tmp_path):
    assert _suggested_path(tmp_path, "src/app.py") == "src/app.py"


@pytest.mark.parametrize(
    "file_path",
    [
        pytest.param("src/a\nb.py", id="newline"),
        pytest.param("src/a\tb\x1b[2K.py", id="tab-and-esc"),
        pytest.param("src/" + "a name with spaces " * 6 + ".py", id="long-with-spaces"),
        pytest.param("src/app.py", id="control-plain"),
    ],
)
def test_the_suggested_yaml_holds_each_key_on_one_line(tmp_path, file_path):
    """The yaml is pasted into a config, so each key is written on one line,
    whatever the path holds and however long it is."""
    import yaml

    result = _suggest(tmp_path, file_path)

    assert result["success"] is True, result
    assert len(result["yaml"].splitlines()) == len(result["json"]), result["yaml"]
    assert yaml.safe_load(result["yaml"]) == result["json"], result["yaml"]
    assert "\x1b" not in result["yaml"] and "\t" not in result["yaml"], result
