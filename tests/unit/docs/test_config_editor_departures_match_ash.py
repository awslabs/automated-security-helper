"""ASH does what each row of the configuration editor's departure table says.

The editor's messages module (docs/content/assets/javascripts/config-editor/messages.js)
lists the places where its verdict differs from the schema's, because ASH reads a file
differently from its schema. Each row gives the severity the editor shows, and the
severity states what a scan does: an error is a file a scan refuses (exit 3), and a
warning or a note is a file it loads.

This file asks ASH instead of trusting the table. It reads the rows out of messages.js,
so the table stays the one source, takes the input of each row from the cases of the
shared corpus that carry an editor verdict, writes it as a config file, and runs ASH's
own file-load route over it: the loader every scan goes through (the file, its spellings
folded, the model built under strict validation), and the config checker that reports
what a scan tolerates. Then it requires ASH's outcome to be the one the row states, and
the facts each row rests on: the field a refused reference names, the words of the
clash, the warning ASH gives, the list a comma string reads as, and the section a
respelled name lands in.

Two controls show that the comparison can fail: a row that claims a refusal ASH does not
give, and a row that claims a tolerance ASH does not give.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config import plugin_section_names as names
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.config.resolve_config import load_config_file
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "docs" / "editor-tests" / "fixtures"
EDITOR_MODULES = ROOT / "docs" / "content" / "assets" / "javascripts" / "config-editor"
MESSAGES = EDITOR_MODULES / "messages.js"
BLOCK = json.loads((FIXTURES / "editor-data.json").read_text(encoding="utf-8"))
CORPUS = json.loads((FIXTURES / "validator-corpus.json").read_text(encoding="utf-8"))
NOTED = [case for case in CORPUS["cases"] if "editor" in case]

ROW = re.compile(
    r"row:\s*'(?P<row>[a-z-]+)',\s*schema:\s*'(?P<schema>valid|invalid)',"
    r"\s*editor:\s*'(?P<editor>error|warning|note)',"
)


def parse_departures(source: str) -> dict[str, dict[str, str]]:
    """The rows of the table, as { row: { schema, editor } }, read out of the source."""
    return {
        match["row"]: {"schema": match["schema"], "editor": match["editor"]}
        for match in ROW.finditer(source)
    }


DEPARTURES = parse_departures(MESSAGES.read_text(encoding="utf-8"))

#: A value of each kind a typed field takes, to set a variable to.
FITTING = {"boolean": "true", "integer": "5", "number": "1.5"}


def _date(text: str):
    """The value YAML reads an unquoted date or datetime as."""
    return datetime.fromisoformat(text) if len(text) > 10 else date.fromisoformat(text)


def _with_dates(instance, pointers):
    """`instance` with a date where the file wrote an unquoted one, at each pointer."""
    result = json.loads(json.dumps(instance))
    for pointer in pointers:
        tokens = [
            token.replace("~1", "/").replace("~0", "~")
            for token in pointer.split("/")[1:]
        ]
        if not tokens:
            return _date(result)
        node = result
        for token in tokens[:-1]:
            node = node[int(token)] if isinstance(node, list) else node[token]
        last = int(tokens[-1]) if isinstance(node, list) else tokens[-1]
        node[last] = _date(node[last])
    return result


def _document(path: str, instance, options=None):
    """The configuration document that holds `instance` at the field `path`.

    A case's options name the pointers of the values the file writes as unquoted dates.
    """
    document = _with_dates(instance, (options or {}).get("unquotedDates", []))
    for key in reversed(path.split(".") if path else []):
        document = {key: document}
    return document


def _references(path: str, instance) -> list[tuple[str, list[str]]]:
    """(field path, variables) of each field that holds a reference in `instance`."""
    found: list[tuple[str, list[str]]] = []

    def walk(prefix: str, node) -> None:
        if isinstance(node, str):
            if node.startswith(("${", "!ENV ")):
                found.append((prefix, re.findall(r"\$\{(\w+)", node)))
        elif isinstance(node, dict):
            for key, value in node.items():
                walk(f"{prefix}.{key}" if prefix else key, value)
        elif isinstance(node, list):
            for item in node:
                walk(f"{prefix}[]", item)

    walk(path, instance)
    return found


def _variables(instance) -> list[str]:
    """The environment variables the references written in `instance` read."""
    return re.findall(r"\$\{(\w+)", json.dumps(instance))


class _Dumper(yaml.SafeDumper):
    """Writes a string the editor holds as `!ENV <reference>` as a file tags it."""


def _represent_string(dumper: yaml.SafeDumper, value: str):
    if value.startswith("!ENV "):
        return dumper.represent_scalar("!ENV", value.removeprefix("!ENV "))
    return dumper.represent_scalar("tag:yaml.org,2002:str", value)


_Dumper.add_representer(str, _represent_string)


def _write(document, tmp_path, name: str = ".ash.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.dump(document, Dumper=_Dumper), encoding="utf-8")
    return path


def _load(document, tmp_path, name: str = ".ash.yaml"):
    """ASH's file-load route: (config, None) when it accepts, (None, error) when not."""
    path = _write(document, tmp_path, name)
    try:
        _, config = load_config_file(path, source_dir=tmp_path)
    except ASHConfigValidationError as error:
        return None, f"{error}\n{getattr(error, 'validation_error', '')}"
    return config, None


def _check(document, tmp_path):
    """What the config checker says about the document written as a config file."""
    path = _write(document, tmp_path)
    return ConfigValidator.check_config_file(path, source_dir=tmp_path)


def _assert_claim(row: str, claim: str, document, error) -> None:
    """The row's severity states the outcome: an error is a refusal, the rest a load."""
    refused = error is not None
    assert refused == (claim == "error"), (
        f"{row}: the table says {claim}, and ASH "
        f"{'refused' if refused else 'accepted'} {document!r}: {error}"
    )


def _facts(
    row: str, case: dict, document, config, error, tmp_path, monkeypatch
) -> None:
    """The facts a row rests on, read from ASH's own outcome."""
    instance = case["instance"]
    if row == "reference-in-typed-field":
        # A variable that is unset has the loader refuse the file before the field
        # is read. Set to a value that fits the field, the reference is still
        # refused at the field, and the refusal names it.
        typed = [
            (field_path, variables)
            for field_path, variables in _references(case["path"], instance)
            if not BLOCK["fields"][field_path]["envAccepted"]
        ]
        assert typed, "the case holds no reference at a field that refuses one"
        for field_path, variables in typed:
            value = FITTING[BLOCK["fields"][field_path]["kind"]]
            for variable in variables:
                monkeypatch.setenv(variable, value)
        _, resolved = _load(document, tmp_path, "set.yaml")
        assert resolved is not None, "ASH loaded the file with its variables set"
        for field_path, _ in typed:
            leaf = field_path.rsplit(".", 1)[-1]
            assert leaf in resolved, (leaf, resolved)
    elif row == "ambiguous-plugin-spellings":
        assert "ambiguous, keep one" in error, error
    elif row == "unknown-key-in-list-entry":
        warned = config._resolution_warnings
        assert any("ruleId" in text for text in warned), warned
        # The same file is refused once it asks to fail on unknown keys.
        _, fatal = _load({**document, "fail_on_unknown_keys": True}, tmp_path, "f.yaml")
        assert fatal is not None and "ruleId" in fatal, fatal
    elif row == "comma-separated-output-formats":
        text = instance if isinstance(instance, str) else instance["output_formats"]
        formats = [getattr(item, "value", item) for item in config.output_formats]
        # ASH splits on commas, strips each piece and drops the empty ones.
        assert formats == [piece.strip() for piece in text.split(",") if piece.strip()]
    elif row == "unquoted-date":
        # ASH reads the date as a date and refuses it where text belongs.
        for pointer in case["options"]["unquotedDates"]:
            field = pointer.rsplit("/", 1)[-1]
            assert field in error or "put it in quotes" in error, (field, error)
    elif row == "unknown-top-level-key":
        check = _check(document, tmp_path)
        unknown = [key for key in instance if key not in AshConfig.model_fields]
        assert check.scan_accepts, check.errors
        for key in unknown:
            assert not hasattr(config, key)
            text = f"Unknown top-level field '{key}' - a scan ignores it"
            assert text in check.warnings, check.warnings
    elif row == "internal-top-level-field":
        check = _check(document, tmp_path)
        want = BLOCK["constants"]["invalidTopLevelFieldWarning"]
        assert check.scan_accepts, check.errors
        assert want.replace("{field}", "build") in check.warnings, check.warnings
    elif row == "plugin-section-spelling":
        kind = case["path"]
        declared = names.declared_section_names(kind)
        for key, value in instance.items():
            target = names.declared_target(declared, key)
            if target is None or target == key:
                continue
            # A declared spelling beside a variant wins key by key.
            written = instance.get(target, value)
            section = getattr(getattr(config, kind), target.replace("-", "_"))
            assert section.enabled == written["enabled"], (kind, key, target)
    else:  # pragma: no cover - a new row needs its facts written here
        pytest.fail(f"no facts are checked for the row {row}")


@pytest.mark.parametrize("case", NOTED, ids=[case["id"] for case in NOTED])
def test_ash_does_what_the_rows_of_the_case_say(case, tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for variable in _variables(case["instance"]):
        monkeypatch.delenv(variable, raising=False)
    document = _document(case["path"], case["instance"], case.get("options"))
    config, error = _load(document, tmp_path)
    # The editor refuses a file exactly when ASH does.
    assert case["editor"]["valid"] == (error is None), (case["id"], error)
    for finding in case["editor"]["findings"]:
        row = finding["row"]
        assert row in DEPARTURES, f"the table has no row {row}"
        assert DEPARTURES[row]["editor"] == finding["severity"], (case["id"], row)
        _assert_claim(row, DEPARTURES[row]["editor"], document, error)
        _facts(row, case, document, config, error, tmp_path, monkeypatch)


def test_the_table_is_read_whole_and_each_row_is_met_by_a_case():
    met = {finding["row"] for case in NOTED for finding in case["editor"]["findings"]}
    assert DEPARTURES, "messages.js holds no table of departures"
    assert set(DEPARTURES) == met


def test_the_reader_of_the_table_takes_a_row_and_leaves_what_is_not_one():
    source = (
        "{ row: 'a-b', schema: 'valid', editor: 'error', reason: 'x' },\n"
        "{ row: 'c', schema: 'maybe', editor: 'error' },\n"
        "{ row: 'd', editor: 'note' }"
    )
    assert parse_departures(source) == {"a-b": {"schema": "valid", "editor": "error"}}
    assert parse_departures("nothing here") == {}


def test_a_row_that_claims_a_refusal_ash_does_not_give_is_caught(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    case = next(item for item in NOTED if item["id"] == "scanners-spelling-variant-ok")
    document = _document(case["path"], case["instance"])
    _, error = _load(document, tmp_path)
    assert error is None
    with pytest.raises(AssertionError):
        _assert_claim("plugin-section-spelling", "error", document, error)


VECTORS = json.loads(
    (FIXTURES / "output-format-vectors.json").read_text(encoding="utf-8")
)
READINGS = [
    pytest.param(group, code, id=f"{group['id']}-{code:x}")
    for group in VECTORS["groups"]
    for code in group["codePoints"]
]


@pytest.mark.parametrize(("group", "code"), READINGS)
def test_ash_reads_a_string_of_output_formats_as_the_vectors_say(
    group, code, tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    text = group["template"].replace("{c}", chr(code))
    config, error = _load({"output_formats": text}, tmp_path)
    if group["formats"] is None:
        assert error is not None, f"ASH loaded {text!r}"
    else:
        assert error is None, error
        formats = [getattr(item, "value", item) for item in config.output_formats]
        assert formats == group["formats"]


ENTRY_TABLE = re.compile(
    r"export const ENTRY_MODELS = Object\.freeze\(\{(?P<body>.*?)\n\}\);", re.DOTALL
)
ENTRY_MODEL = re.compile(
    r"^\s+(?P<name>\w+): \{ noun: '(?P<noun>[^']+)',", re.MULTILINE
)


def parse_entry_models(source: str) -> dict[str, str]:
    """The entry models of the table in messages.js, as { definition: its noun }."""
    table = ENTRY_TABLE.search(source)
    if table is None:
        return {}
    return {
        match["name"]: match["noun"] for match in ENTRY_MODEL.finditer(table["body"])
    }


ENTRY_MODELS = parse_entry_models(MESSAGES.read_text(encoding="utf-8"))

ENTRY = {"path": "a", "reason": "b"}
UNKNOWN = {**ENTRY, "bogus": 1}

#: A document for each place an entry model sits, each holding one key it does not know.
ENTRY_DOCUMENTS = {
    "AshSuppression": [{"global_settings": {"suppressions": [UNKNOWN]}}],
    "AshExclusion": [
        {"global_settings": {"exclusions": [{**UNKNOWN, "rule_id": "r"}]}},
    ],
    "IgnorePathWithReason": [
        {"global_settings": {"ignore_paths": [UNKNOWN]}},
        {"scanners": {"bandit": {"options": {"excluded_paths": [UNKNOWN]}}}},
    ],
    "SuppressionScope": [
        {"global_settings": {"suppressions": [{**ENTRY, "scope": {"bogus": 1}}]}},
    ],
}
PLACES = [
    pytest.param(model, document, id=f"{model}-{index}")
    for model, documents in ENTRY_DOCUMENTS.items()
    for index, document in enumerate(documents)
]


def test_the_table_of_entry_models_is_read_whole_and_each_model_has_a_document():
    assert ENTRY_MODELS, "messages.js holds no table of entry models"
    assert set(ENTRY_MODELS) == set(ENTRY_DOCUMENTS)


@pytest.mark.parametrize(("model", "document"), PLACES)
def test_ash_warns_about_an_unknown_key_in_an_entry_and_loads_the_file(
    model, document, tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config, error = _load(document, tmp_path)
    assert error is None, (model, error)
    assert any("bogus" in text for text in config._resolution_warnings), model


@pytest.mark.parametrize(("model", "document"), PLACES)
def test_ash_refuses_the_same_key_once_the_file_asks_to_fail_on_unknown_keys(
    model, document, tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _, error = _load({**document, "fail_on_unknown_keys": True}, tmp_path)
    assert error is not None and "bogus" in error, (model, error)


def test_a_row_that_claims_a_tolerance_ash_does_not_give_is_caught(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    case = next(item for item in NOTED if item["id"] == "scanners-two-variants-ok")
    document = _document(case["path"], case["instance"])
    _, error = _load(document, tmp_path)
    assert error is not None
    for claim in ("warning", "note"):
        with pytest.raises(AssertionError):
            _assert_claim("ambiguous-plugin-spellings", claim, document, error)
