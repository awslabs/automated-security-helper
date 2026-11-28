# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The configuration editor's validator and Python's jsonschema give one verdict.

docs/editor-tests/fixtures/validator-corpus.json holds the cases that the editor's
validator (docs/content/assets/javascripts/config-editor/validate.js) is tested on. This
file is the other half of that test: it takes each case's verdict, and the one keyword
and instance pointer that failed, from ``jsonschema.Draft202012Validator`` run on the
same schema and instance, and requires the corpus to say the same. The node test then
requires the validator to say what the corpus says, so the two checks together tie the
validator to jsonschema through one shared file.

The schema is the one in the data block fixture (editor-data.json), and the instance of
a case is checked against the field the case names, the way the editor checks a field.
The keywords that schema does not use come with their own small schemas.

Besides the verdicts, the file checks the corpus: every keyword the schema uses has a
case that passes and a case that fails, and every keyword that can fail on its own is
the named failure of some case, so a keyword cannot be added to the schema or dropped
from the validator without a case to say so.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "docs" / "editor-tests" / "fixtures"
BLOCK = json.loads((FIXTURES / "editor-data.json").read_text(encoding="utf-8"))
CORPUS = json.loads((FIXTURES / "validator-corpus.json").read_text(encoding="utf-8"))
CASES = [*CORPUS["cases"], *CORPUS["keywordCases"]]

#: The assertion keywords the editor's validator implements, and nothing else.
ASSERTIONS = frozenset(
    {
        "additionalProperties",
        "anyOf",
        "const",
        "enum",
        "exclusiveMinimum",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "propertyNames",
        "required",
        "type",
        "$ref",
    }
)

#: The keywords that name a failure of their own. ``properties``, ``$ref`` and
#: ``propertyNames`` only pass on the failures of the schemas they hold, and an
#: ``items`` that holds a schema does the same, so a failure never names them. A
#: schema ``items: false`` does name ``items``.
FAILING_KEYWORDS = ASSERTIONS - {"properties", "$ref", "propertyNames"}


def _pointer(path) -> str:
    """The JSON pointer of a path of keys and indexes, as the corpus writes it."""
    return "".join(
        "/" + str(part).replace("~", "~0").replace("/", "~1") for part in path
    )


def _schema_for(case: dict) -> dict:
    """The schema a case is checked against: its own, or the schema of its field."""
    if "schema" in case:
        return case["schema"]
    root = BLOCK["validationSchema"]
    if case["path"] == "":
        return root
    pointer = BLOCK["fields"][case["path"]]["schemaPointer"]
    # The field's schema sits inside the root document, so its references resolve
    # against the same definitions the root carries.
    return {"$ref": pointer, "$defs": root["$defs"]}


def _failures(case: dict) -> set[tuple[str, str]]:
    """(instance pointer, keyword) of every error jsonschema reports for a case.

    An error that comes from a false schema carries no keyword in jsonschema, and the
    corpus names it ``false``.
    """
    validator = Draft202012Validator(_schema_for(case))
    return {
        (_pointer(error.absolute_path), error.validator or "false")
        for error in validator.iter_errors(case["instance"])
    }


def _resolve(root: dict, pointer: str):
    """The node of ``root`` that a local ``#/...`` pointer names."""
    node = root
    for token in pointer.removeprefix("#").split("/")[1:]:
        node = node[token.replace("~1", "/").replace("~0", "~")]
    return node


def _keywords_reached(
    root: dict, schema, *, every_definition: bool = False
) -> set[str]:
    """Every keyword in ``schema`` and in each schema it references, however deep.

    The definitions in ``$defs`` are walked only through a reference to them, unless
    ``every_definition`` asks for all of them, so the keywords of one field's schema are
    not the keywords of the whole document.
    """
    seen: set[str] = set()
    keywords: set[str] = set()

    def walk(node) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            keywords.add(key)
            if key == "$ref" and value not in seen:
                seen.add(value)
                walk(_resolve(root, value))
            elif key == "$defs" and every_definition:
                for child in value.values():
                    walk(child)
            elif key == "properties":
                for child in value.values():
                    walk(child)
            elif key == "anyOf":
                for child in value:
                    walk(child)
            elif key in ("items", "additionalProperties", "propertyNames"):
                walk(value)

    walk(schema)
    return keywords - {"$defs"}


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_the_corpus_verdict_and_failure_are_jsonschemas(case):
    failures = _failures(case)
    assert (not failures) == case["valid"], (
        f"jsonschema reports {sorted(failures)} for {case['instance']!r}, "
        f"and the corpus says valid is {case['valid']}"
    )
    expected = set() if case["valid"] else {(case["pointer"], case["keyword"])}
    assert failures == expected


def test_the_corpus_has_no_duplicate_case_ids():
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids))


def test_the_schema_uses_only_keywords_the_validator_implements():
    root = BLOCK["validationSchema"]
    used = _keywords_reached(root, root, every_definition=True)
    assert used <= ASSERTIONS, f"the schema uses {sorted(used - ASSERTIONS)} as well"
    assert used, "the schema holds no keyword, so the check proves nothing"


def test_every_field_path_in_the_corpus_is_a_field_of_the_block():
    paths = {case["path"] for case in CORPUS["cases"] if case["path"] != ""}
    assert paths <= set(BLOCK["fields"]), sorted(paths - set(BLOCK["fields"]))


def test_every_field_of_the_block_has_cases_that_pass_and_fail():
    """Each field has an instance that passes its schema and one that fails it."""
    by_path: dict[str, set[bool]] = {}
    for case in CORPUS["cases"]:
        by_path.setdefault(case["path"], set()).add(case["valid"])
    for path in BLOCK["fields"]:
        assert by_path.get(path) == {True, False}, f"{path}: {by_path.get(path)}"


def test_every_keyword_has_a_case_that_passes_and_a_case_that_fails():
    root = BLOCK["validationSchema"]
    passing: set[str] = set()
    failing: set[str] = set()
    for case in CASES:
        schema = _schema_for(case)
        reached = _keywords_reached(schema if "schema" in case else root, schema)
        (passing if case["valid"] else failing).update(reached)
    assert ASSERTIONS <= passing, sorted(ASSERTIONS - passing)
    assert ASSERTIONS <= failing, sorted(ASSERTIONS - failing)


def test_every_keyword_that_can_fail_on_its_own_is_the_named_failure_of_a_case():
    named = {case["keyword"] for case in CASES if not case["valid"]}
    assert FAILING_KEYWORDS <= named, sorted(FAILING_KEYWORDS - named)


#: The rows of the editor's divergence table, which are the places the editor shows
#: something other than the schema's verdict. Each has at least one case below.
DIVERGENCE_ROWS = frozenset(
    {
        "reference-in-typed-field",
        "ambiguous-plugin-spellings",
        "unknown-key-in-list-entry",
        "comma-separated-output-formats",
        "unknown-top-level-key",
        "internal-top-level-field",
        "plugin-section-spelling",
        "unquoted-date",
        "variant-section-contents",
    }
)


def test_the_editor_notes_of_the_corpus_are_well_formed_and_cover_every_row():
    named: set[str] = set()
    for case in CASES:
        editor = case.get("editor")
        if editor is None:
            continue
        assert editor["findings"], f"{case['id']} has an editor object with no finding"
        severities = {finding["severity"] for finding in editor["findings"]}
        assert severities <= {"error", "warning", "note"}, case["id"]
        # The editor refuses a file exactly when one of its findings is an error.
        assert editor["valid"] == ("error" not in severities), case["id"]
        named |= {finding["row"] for finding in editor["findings"]}
    assert named == DIVERGENCE_ROWS, sorted(named ^ DIVERGENCE_ROWS)


def test_a_case_whose_editor_verdict_differs_names_the_schema_verdict_it_departs_from():
    """Both directions occur: the schema accepts what the editor refuses, and the
    schema refuses what the editor accepts with a warning."""
    noted = [c for c in CASES if "editor" in c]
    stricter = [c for c in noted if c["valid"] and not c["editor"]["valid"]]
    looser = [c for c in noted if not c["valid"] and c["editor"]["valid"]]
    assert stricter, "no case where the editor refuses what the schema accepts"
    assert looser, "no case where the editor accepts what the schema refuses"
