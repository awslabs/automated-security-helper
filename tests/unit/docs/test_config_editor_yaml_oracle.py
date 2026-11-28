"""The configuration editor's YAML corpus agrees with ASH's own YAML loader.

docs/editor-tests/fixtures/yaml-oracle-*.json holds the inputs the editor's YAML
reader and patcher are tested with. Each reading case is a YAML text with either
the value ASH's loader returns for it or the refusal the reader must make. Each
planted edit is a text before, an edit, and the exact text after. The editor's
node tests read the same files, so a value pinned here is a value the reader has
to produce.

This test is the half that needs Python: it loads every text with the loader a
scan uses (``load_yaml_config`` with references kept as written), and checks

* the value the corpus pins,
* for refusals, that ASH fails or loads the text as the case says, and that the
  line and column the case names are the ones PyYAML reports when it fails,
* for each planted edit, that the text after reads as the text before with the
  edit applied, so the exact text the patcher must write also means what the
  edit says.

Values are compared in a JSON projection: integers beyond 2**53, floats, dates
and timestamps, mappings with keys that are not plain strings, and text with
control characters are written as small tagged objects, so the corpus holds
what the loader built and a JavaScript reader can say the same thing.
"""

import datetime
import json
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import load_yaml_config

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "docs" / "editor-tests" / "fixtures"
SAFE_INTEGER = 2**53 - 1
INPUT_TOKENS = {"<BSu>": "\\u", "<BSU>": "\\U", "<SOH>": chr(1)}
REFUSAL_CODES = {
    "alias",
    "anchor",
    "character",
    "complex-key",
    "constructor",
    "directive",
    "merge",
    "second-document",
    "syntax",
    "tab",
    "tag",
    "too-large",
}


def read_corpus(kind):
    cases = []
    for path in sorted(FIXTURES.glob("yaml-oracle-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["format"] == "yaml-oracle/1", path.name
        cases.extend(data.get(kind, []))
    return cases


READING_CASES = read_corpus("cases")
EDIT_CASES = read_corpus("edits")


def block_text(block):
    """The text of a ``{"lines": [...]}`` or ``{"text": "..."}`` object."""
    if "text" in block:
        text = block["text"]
    else:
        text = "\n".join(block["lines"]) + "\n"
    for token, replacement in INPUT_TOKENS.items():
        text = text.replace(token, replacement)
    return text


def case_text(case):
    if "fill" in case:
        fill = case["fill"]
        return fill["prefix"] + fill["char"] * fill["count"]
    return block_text(case)


def load(text):
    return load_yaml_config(text, env="written")


def load_error(text):
    """The error ASH's loader raises for the text, or None when it loads."""
    try:
        load(text)
    except Exception as error:
        return error
    return None


def unsafe_character(character):
    code = ord(character)
    return (
        (code < 0x20 and code not in (0x09, 0x0A, 0x0D))
        or 0x7F <= code <= 0xA0
        or code in (0x2028, 0x2029, 0xFEFF)
        or 0xD800 <= code <= 0xDFFF
    )


def project(value):
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > SAFE_INTEGER:
            return {"$int": str(value)}
        return value
    if isinstance(value, float):
        return {"$float": repr(value)}
    if isinstance(value, str):
        if any(unsafe_character(character) for character in value):
            return {"$codes": [ord(character) for character in value]}
        return value
    if isinstance(value, datetime.datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, datetime.date):
        return {"$date": value.isoformat()}
    if isinstance(value, list):
        return [project(item) for item in value]
    if isinstance(value, dict):
        if all(isinstance(key, str) and not key.startswith("$") for key in value):
            return {key: project(item) for key, item in value.items()}
        return {"$map": [[project(key), project(item)] for key, item in value.items()]}
    raise TypeError(f"the corpus has no projection for {type(value).__name__}")


def same_float(left, right):
    return repr(float(left)) == repr(float(right))


def same(expected, actual):
    if isinstance(expected, dict) and isinstance(actual, dict):
        if set(expected) == {"$float"} and set(actual) == {"$float"}:
            return same_float(expected["$float"], actual["$float"])
        return set(expected) == set(actual) and all(
            same(expected[key], actual[key]) for key in expected
        )
    if isinstance(expected, list) and isinstance(actual, list):
        return len(expected) == len(actual) and all(
            same(left, right) for left, right in zip(expected, actual)
        )
    return type(expected) is type(actual) and expected == actual


def short(value):
    return json.dumps(value, ensure_ascii=True)[:160]


def difference(expected, actual, path="value"):
    """Where the two projections first differ, or None when they agree."""
    if same(expected, actual):
        return None
    both_mappings = isinstance(expected, dict) and isinstance(actual, dict)
    if both_mappings and "$float" not in expected:
        for key in sorted(set(expected) | set(actual)):
            if key not in expected:
                return f"{path}.{key}: not expected, loader gave {short(actual[key])}"
            if key not in actual:
                return f"{path}.{key}: missing, expected {short(expected[key])}"
            found = difference(expected[key], actual[key], f"{path}.{key}")
            if found:
                return found
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) == len(actual):
            for index, (left, right) in enumerate(zip(expected, actual)):
                found = difference(left, right, f"{path}[{index}]")
                if found:
                    return found
    return f"{path}: expected {short(expected)}, loader gave {short(actual)}"


def check_reading_case(case):
    text = case_text(case)
    if "refuse" not in case:
        error = load_error(text)
        assert error is None, f"ASH's loader refuses this text: {error}"
        found = difference(case["value"], project(load(text)))
        assert found is None, found
        return
    refuse = case["refuse"]
    assert refuse["code"] in REFUSAL_CODES, refuse["code"]
    ash = case.get("ash", "error")
    if ash == "skip":
        return
    error = load_error(text)
    if ash == "loads":
        assert error is None, f"ASH's loader refuses this text: {error}"
        return
    assert error is not None, "ASH's loader reads this text, the case says it fails"
    mark = getattr(error, "problem_mark", None)
    if mark is not None:
        reported = (mark.line + 1, mark.column + 1)
        assert reported == (refuse["line"], refuse["column"]), (
            f"PyYAML reports line {reported[0]}, column {reported[1]}: {error}"
        )


@pytest.mark.parametrize("case", READING_CASES, ids=lambda case: case["id"])
def test_the_loader_reads_each_case_as_the_corpus_says(case):
    check_reading_case(case)


def edit_value(raw):
    """What an edit's value is once ASH's loader has read the text that holds it.

    A value is written in the corpus's own projection, so a float is
    ``{"$float": "2.0"}``, an integer beyond 2**53 is ``{"$int": "9007199254740995"}``
    and a mapping with keys that are not plain strings is
    ``{"$map": [[key, value], ...]}``; all three are what ``project`` gives for what
    the loader builds, so they stand for themselves here. A float written as a bare
    JSON number would read as an integer in JavaScript, and an integer beyond 2**53
    would be rounded by it, which is why the corpus never does either.
    """
    if isinstance(raw, dict) and "$ref" in raw:
        return ("!ENV " if raw.get("explicit") else "") + raw["$ref"]
    if isinstance(raw, list):
        return [edit_value(item) for item in raw]
    if isinstance(raw, dict):
        return {key: edit_value(item) for key, item in raw.items()}
    return raw


def is_typed_map(node):
    """A mapping the projection writes as ``{"$map": [[key, value], ...]}``."""
    return isinstance(node, dict) and set(node) == {"$map"}


def pair_index(node, step):
    """Where the pair whose key is the string ``step`` sits in a typed map, or None.

    A path step is a string or a list position, so it never names a key that is
    not a string: the key 1 and the key "1" are two pairs, and "1" reaches one.
    """
    for index, (key, _) in enumerate(node["$map"]):
        if isinstance(key, str) and key == step:
            return index
    return None


def typed_map_of(pairs):
    """The projection of a mapping with these pairs, which is a plain object again
    once every key is a string that does not start with a dollar sign."""
    if all(isinstance(key, str) and not key.startswith("$") for key, _ in pairs):
        return dict(pairs)
    return {"$map": pairs}


def get_at(node, path):
    for step in path:
        if isinstance(step, int):
            if not isinstance(node, list) or step >= len(node):
                return None
            node = node[step]
        elif is_typed_map(node):
            index = pair_index(node, step)
            if index is None:
                return None
            node = node["$map"][index][1]
        else:
            if not isinstance(node, dict) or step not in node:
                return None
            node = node[step]
    return node


def set_at(node, path, new):
    if not path:
        return new
    head, rest = path[0], path[1:]
    if isinstance(head, int):
        items = list(node)
        items[head] = set_at(items[head], rest, new)
        return items
    if is_typed_map(node):
        pairs = [[key, item] for key, item in node["$map"]]
        index = pair_index(node, head)
        if index is None:
            pairs.append([head, set_at(None, rest, new)])
        else:
            pairs[index][1] = set_at(pairs[index][1], rest, new)
        return {"$map": pairs}
    mapping = dict(node) if isinstance(node, dict) else {}
    mapping[head] = set_at(mapping.get(head), rest, new)
    return mapping


def delete_at(node, path):
    head, rest = path[0], path[1:]
    if isinstance(head, int):
        if not isinstance(node, list) or head >= len(node):
            return node
        items = list(node)
        if rest:
            items[head] = delete_at(items[head], rest)
        else:
            del items[head]
        return items
    if is_typed_map(node):
        index = pair_index(node, head)
        if index is None:
            return node
        pairs = [[key, item] for key, item in node["$map"]]
        if rest:
            pairs[index][1] = delete_at(pairs[index][1], rest)
        else:
            del pairs[index]
        return typed_map_of(pairs)
    if not isinstance(node, dict) or head not in node:
        return node
    mapping = dict(node)
    if rest:
        mapping[head] = delete_at(mapping[head], rest)
    else:
        del mapping[head]
    return mapping


def apply_edit(document, edit):
    path = edit["path"]
    if edit["op"] == "set":
        return set_at(document, path, edit_value(edit["value"]))
    if edit["op"] == "delete":
        return delete_at(document, path)
    assert edit["op"] == "append", edit["op"]
    current = get_at(document, path)
    items = list(current) if isinstance(current, list) else []
    return set_at(document, path, items + [edit_value(edit["value"])])


CHANGING_EDITS = [case for case in EDIT_CASES if case["how"] in ("patch", "reemit")]
UNCHANGING_EDITS = [case for case in EDIT_CASES if case["how"] == "none"]
REFUSED_EDITS = [case for case in EDIT_CASES if case["how"] == "refused"]


@pytest.mark.parametrize("case", CHANGING_EDITS, ids=lambda case: case["id"])
def test_the_text_after_an_edit_reads_as_the_text_before_with_the_edit_applied(case):
    before = project(load(block_text(case["before"])))
    after = project(load(block_text(case["after"])))
    expected = apply_edit(before, case["edit"])
    found = difference(expected, after)
    assert found is None, found


@pytest.mark.parametrize("case", UNCHANGING_EDITS, ids=lambda case: case["id"])
def test_an_edit_that_changes_nothing_changes_nothing_in_the_value(case):
    before = project(load(block_text(case["before"])))
    assert same(before, apply_edit(before, case["edit"]))


@pytest.mark.parametrize("case", REFUSED_EDITS, ids=lambda case: case["id"])
def test_a_refused_edit_starts_from_the_text_ash_reads_as_the_case_says(case):
    error = load_error(block_text(case["before"]))
    if case["reason"] == "unreadable":
        assert error is not None, "ASH reads this text, so the editor should too"
    else:
        assert error is None, f"ASH refuses this text: {error}"


def test_every_case_has_its_own_id():
    ids = [case["id"] for case in READING_CASES + EDIT_CASES]
    assert len(ids) == len(set(ids))
    assert len(READING_CASES) >= 100
    assert len(EDIT_CASES) >= 50


def test_the_comparison_tells_a_boolean_from_the_word_and_the_number():
    actual = project(load("a: yes\n"))
    assert same({"a": True}, actual)
    assert not same({"a": "yes"}, actual)
    assert not same({"a": 1}, actual)
    assert not same({"a": False}, actual)


def test_the_comparison_tells_float_zeros_apart_and_nan_from_itself():
    assert not same({"$float": "0.0"}, {"$float": "-0.0"})
    assert same({"$float": "nan"}, {"$float": "nan"})
    assert same({"$float": "1500.0"}, {"$float": "1.5e3"})


def test_a_planted_wrong_value_in_a_case_is_reported():
    case = next(item for item in READING_CASES if item["id"] == "bool-words")
    wrong = {**case, "value": {**case["value"], "g": False}}
    with pytest.raises(AssertionError, match=r"value\.g"):
        check_reading_case(wrong)


def test_a_planted_wrong_position_in_a_refusal_is_reported():
    case = next(item for item in READING_CASES if item["id"] == "alias")
    wrong = {**case, "refuse": {**case["refuse"], "column": 99}}
    with pytest.raises(AssertionError, match="PyYAML reports line 2"):
        check_reading_case(wrong)


def test_a_planted_edit_that_means_something_else_is_reported():
    case = next(item for item in EDIT_CASES if item["id"] == "set-plain-string")
    before = project(load(block_text(case["before"])))
    wrong = apply_edit(before, {**case["edit"], "value": "four"})
    assert difference(wrong, project(load(block_text(case["after"]))))


def test_the_edit_helpers_reach_into_a_mapping_with_typed_keys():
    document = project(load("m: {1: a, l: x}\n"))
    assert document == {"m": {"$map": [[1, "a"], ["l", "x"]]}}
    assert get_at(document, ["m", "l"]) == "x"
    assert set_at(document, ["m", "l"], "y") == {"m": {"$map": [[1, "a"], ["l", "y"]]}}
    assert set_at(document, ["m", "z"], 2) == {
        "m": {"$map": [[1, "a"], ["l", "x"], ["z", 2]]}
    }
    assert delete_at(document, ["m", "l"]) == {"m": {"$map": [[1, "a"]]}}
    assert delete_at(document, ["m", "nothing"]) == document


def test_a_string_step_never_reaches_a_key_that_is_not_a_string():
    document = project(load('m: {1: a, "1": b}\n'))
    assert document == {"m": {"$map": [[1, "a"], ["1", "b"]]}}
    assert get_at(document, ["m", "1"]) == "b"
    assert set_at(document, ["m", "1"], "c") == {"m": {"$map": [[1, "a"], ["1", "c"]]}}
    assert delete_at(document, ["m", "1"]) == {"m": {"$map": [[1, "a"]]}}
    assert get_at({"m": {"$map": [[1, "a"]]}}, ["m", "1"]) is None


def test_a_mapping_is_a_plain_object_again_once_no_key_starts_with_a_dollar_sign():
    document = project(load("m: {$a: 1, b: 2}\n"))
    assert document == {"m": {"$map": [["$a", 1], ["b", 2]]}}
    assert delete_at(document, ["m", "$a"]) == {"m": {"b": 2}}


def test_a_float_in_an_edit_is_written_in_the_projection_and_compares_as_a_float():
    value = edit_value({"$float": "2.0"})
    assert value == {"$float": "2.0"}
    document = set_at(project(load("a: 1\n")), ["a"], value)
    assert same(document, project(load("a: 2.0\n")))
    assert not same(document, project(load("a: 2\n")))


def test_an_integer_beyond_two_to_the_53_in_an_edit_keeps_every_digit_and_is_not_a_float():
    value = edit_value({"$int": "9007199254740995"})
    assert value == {"$int": "9007199254740995"}
    document = set_at(project(load("limit: 9007199254740993\n")), ["limit"], value)
    assert document == {"limit": {"$int": "9007199254740995"}}
    assert same(document, project(load("limit: 9007199254740995\n")))
    # The integer one below is another value, and so is the float a double would round to.
    assert not same(document, project(load("limit: 9007199254740994\n")))
    assert not same(document, project(load("limit: 9007199254740995.0\n")))
