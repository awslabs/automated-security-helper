"""The spelling table: one row per renamed configuration key, read by every reader.

A row names the model whose field was renamed, the canonical spelling (the
field name), the old spellings the loader still reads, the release that
introduced the canonical spelling and the release that stops accepting the old
ones. The models declare a renamed field through ``renamed_field``; the loader
folds each file's old spellings through ``fold_spellings``; the models apply the
both-spellings rule through ``check_spellings`` when they are built without the
loader; lint, patch pointers and the runtime-patch denials read the same rows.

These tests pin the table's contract, and they pin it on a row a test adds as
well as on the shipped one: a mapping-valued, top-level or section row is
added later, and a row added to the table must reach every reader with no
other edit.
"""

import typing
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set, Type

import pytest
import yaml
from pydantic import AliasChoices, BaseModel, ValidationError

import automated_security_helper
from automated_security_helper.config import spellings
from automated_security_helper.config.ash_config import (
    AshConfig,
    ContentDbStalenessOverride,
)
from automated_security_helper.config.ash_workspace_config import AshWorkspaceConfig
from automated_security_helper.config.config_linter import ConfigLinter, LintCategory
from automated_security_helper.models.core import (
    EXPIRATION_SPELLING_DEPRECATION,
    AshSuppression,
    IgnorePathWithReason,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

ROOT = "automated_security_helper.config.ash_config.AshConfig"
ENTRY_MODEL = "automated_security_helper.models.core.IgnorePathWithReason"
SOURCE = "cfg.yaml"

#: Built from code points, so no file holds the characters themselves.
BACKSLASH = chr(92)
ESCAPE = chr(0x1B)
RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)


def _expires_row() -> spellings.SpellingRow:
    (row,) = [r for r in spellings.ROWS if r.canonical == "expires"]
    return row


def _entry(**fields: Any) -> Dict[str, Any]:
    return {"rule_id": "B101", "path": "src/app.py", "reason": "reviewed", **fields}


def _suppressions(*entries: Dict[str, Any]) -> Dict[str, Any]:
    return {"global_settings": {"suppressions": list(entries)}}


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _with_row(monkeypatch, **fields: Any) -> spellings.SpellingRow:
    """Add a row to the table for one test; every reader reads it from there."""
    row = spellings.SpellingRow(
        kind="key",
        introduced="3.8.0",
        removed_in=None,
        note="a row added by a test",
        **fields,
    )
    monkeypatch.setattr(spellings, "ROWS", (*spellings.ROWS, row))
    return row


# ---------------------------------------------------------------------------
# The rows and the models
# ---------------------------------------------------------------------------


def test_the_shipped_row_renames_the_entry_expiry() -> None:
    row = _expires_row()

    assert row.kind == "key"
    assert row.model == ENTRY_MODEL
    assert row.old == ("expiration",)
    assert row.introduced == "3.8.0"
    assert row.removed_in == "4.0"


@pytest.mark.parametrize("row", spellings.ROWS, ids=lambda r: r.canonical)
def test_every_row_names_a_field_of_its_model(row: spellings.SpellingRow) -> None:
    model = spellings.row_model(row)

    assert row.canonical in model.model_fields
    declared = {
        spelling
        for name, info in model.model_fields.items()
        for spelling in (name, info.alias)
        if spelling
    }
    assert not set(row.old) & declared
    assert row.canonical not in row.old


@pytest.mark.parametrize("row", spellings.ROWS, ids=lambda r: r.canonical)
def test_every_rows_field_is_declared_through_the_table(
    row: spellings.SpellingRow,
) -> None:
    info = spellings.row_model(row).model_fields[row.canonical]

    assert isinstance(info.validation_alias, AliasChoices)
    assert list(info.validation_alias.choices) == [row.canonical, *row.old]
    # No alias, so every dump writes the canonical spelling.
    assert info.alias is None
    assert info.serialization_alias is None


def test_renamed_field_puts_the_canonical_spelling_first() -> None:
    info = spellings.renamed_field(
        "expires", model=ENTRY_MODEL, default=None, description="When it ends."
    )

    assert list(info.validation_alias.choices) == ["expires", "expiration"]
    assert info.alias is None
    assert info.default is None
    assert info.description == "When it ends."


def test_renamed_field_keeps_a_removed_rows_old_spelling(monkeypatch) -> None:
    """At the removal release the model still reads a row's old spelling, so a
    stored record keeps loading; the removal is enforced where documents are read."""
    monkeypatch.setattr(automated_security_helper, "__version__", "4.0.0")
    assert _expires_row().status() == "removed"

    info = spellings.renamed_field("expires", model=ENTRY_MODEL, default=None)

    assert list(info.validation_alias.choices) == ["expires", "expiration"]


def test_rows_for_a_model_include_its_base_classes_rows() -> None:
    assert _expires_row() in spellings.rows_for(AshSuppression)
    assert _expires_row() in spellings.rows_for(IgnorePathWithReason)
    # A model whose own field is spelled ``expiration`` holds no such row.
    assert _expires_row() not in spellings.rows_for(ContentDbStalenessOverride)


def _models_in(annotation: Any) -> List[Type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    return [m for arg in typing.get_args(annotation) for m in _models_in(arg)]


def _models_under(root: Type[BaseModel]) -> Iterator[Type[BaseModel]]:
    seen: Set[Type[BaseModel]] = set()
    stack = [root]
    while stack:
        model = stack.pop()
        if model in seen:
            continue
        seen.add(model)
        yield model
        for info in model.model_fields.values():
            stack.extend(_models_in(info.annotation))


@pytest.mark.parametrize("root", [AshConfig, AshWorkspaceConfig])
def test_every_field_read_under_several_spellings_has_a_row(
    root: Type[BaseModel],
) -> None:
    """A rename declared outside the table would be read by the model alone."""
    missing = []
    for model in _models_under(root):
        for name, info in model.model_fields.items():
            if not isinstance(info.validation_alias, AliasChoices):
                continue
            if not any(r.canonical == name for r in spellings.rows_for(model)):
                missing.append(f"{model.__name__}.{name}")

    assert missing == []


@pytest.mark.parametrize("row", spellings.ROWS, ids=lambda r: r.canonical)
def test_every_rows_model_sits_in_the_configuration(
    row: spellings.SpellingRow,
) -> None:
    assert spellings.entry_paths(spellings.row_model(row))


def test_the_entry_model_sits_in_every_list_that_holds_it() -> None:
    paths = set(spellings.entry_paths(IgnorePathWithReason))

    assert {
        ("global_settings", "ignore_paths"),
        ("global_settings", "suppressions"),
        ("global_settings", "exclusions"),
        ("scanners", "bandit", "options", "excluded_paths"),
    } <= paths


def test_field_spellings_name_every_spelling_a_field_is_read_under() -> None:
    assert spellings.field_spellings(IgnorePathWithReason, "expires") == (
        "expires",
        "expiration",
    )
    assert set(spellings.field_spellings(AshConfig, "mcp_resource_management")) == {
        "mcp_resource_management",
        "mcp-resource-management",
    }


# ---------------------------------------------------------------------------
# Messages and the removal release
# ---------------------------------------------------------------------------


def test_the_rows_messages_are_the_ones_the_entry_model_prints() -> None:
    row = _expires_row()

    assert spellings.deprecation_message(row, "expiration") == (
        EXPIRATION_SPELLING_DEPRECATION
    )
    assert spellings.disagreement_message(row, "expiration") == (
        "expires and expiration are two spellings of one field and disagree; keep one"
    )
    removal = spellings.removal_message(row, "expiration")
    assert "'expiration'" in removal
    assert "'expires'" in removal
    assert "4.0" in removal


@pytest.mark.parametrize(
    "version,removed",
    [
        ("3.8.0", False),
        ("3.99.0", False),
        ("4.0.0rc1", True),
        ("4.0.0", True),
        ("4.1.2", True),
        ("unknown", False),
    ],
)
def test_the_removal_release_is_read_by_release_number(
    version: str, removed: bool
) -> None:
    assert spellings.is_removed(_expires_row(), version) is removed


def test_a_row_with_no_removal_release_is_never_removed(monkeypatch) -> None:
    row = _with_row(monkeypatch, model=ROOT, canonical="project_name", old=("name",))

    assert spellings.is_removed(row, "99.0.0") is False


def test_the_removal_release_is_compared_with_the_running_version(
    monkeypatch,
) -> None:
    monkeypatch.setattr(automated_security_helper, "__version__", "4.0.0")

    assert spellings.running_version() == "4.0.0"
    assert spellings.is_removed(_expires_row()) is True


@pytest.mark.parametrize(
    "version,status",
    [
        ("3.99.0", "live"),
        ("4.0.0rc1", "removed"),
        ("4.0.0", "removed"),
        ("unknown", "live"),
    ],
)
def test_a_rows_status_is_read_from_its_removal_release(
    version: str, status: str
) -> None:
    """Live: the old spelling is read, with a line. Removed: it is refused."""
    assert _expires_row().status(version) == status


def test_a_rows_status_is_read_at_the_running_version(monkeypatch) -> None:
    monkeypatch.setattr(automated_security_helper, "__version__", "4.0.0")

    assert _expires_row().status() == "removed"


def test_a_row_with_no_removal_release_stays_live(monkeypatch) -> None:
    row = _with_row(monkeypatch, model=ROOT, canonical="project_name", old=("name",))

    assert row.status("99.0.0") == "live"


def test_at_the_running_version_a_documents_old_spelling_loads_until_removal() -> None:
    """Fails the day the version reaches a row's release while a document the
    loader reads still loads its old spelling; the model reads it at every release."""
    entry = _entry(expiration="2099-01-01")
    if spellings.is_removed(_expires_row()):
        with pytest.raises(spellings.SpellingRefused):
            spellings.fold_spellings(_suppressions(entry), SOURCE)
    else:
        folded = spellings.fold_spellings(_suppressions(entry), SOURCE)
        (folded_entry,) = folded.document["global_settings"]["suppressions"]
        assert folded_entry["expires"] == "2099-01-01"
        assert "expiration" not in folded_entry
    assert AshSuppression.model_validate(entry).expires == "2099-01-01"


# ---------------------------------------------------------------------------
# fold_spellings: one file's document
# ---------------------------------------------------------------------------


def test_the_fold_renames_the_old_spelling_where_it_stood() -> None:
    entry = {"rule_id": "B101", "expiration": "2099-01-01", "path": "a", "reason": "r"}
    document = _suppressions(entry)

    folded = spellings.fold_spellings(document, SOURCE)

    (folded_entry,) = folded.document["global_settings"]["suppressions"]
    assert list(folded_entry) == ["rule_id", "expires", "path", "reason"]
    assert folded_entry["expires"] == "2099-01-01"
    # What it was given is left as it was.
    assert document == _suppressions(entry)
    assert folded.warnings == (f"Config {SOURCE}: {EXPIRATION_SPELLING_DEPRECATION}",)


def test_the_fold_says_each_spelling_once_per_file() -> None:
    document = {
        "global_settings": {
            "suppressions": [
                _entry(expiration="2099-01-01"),
                _entry(expiration="2099-01-02"),
            ],
            "ignore_paths": [
                {"path": "build/", "reason": "generated", "expiration": "2099-01-03"}
            ],
        }
    }

    assert len(spellings.fold_spellings(document, SOURCE).warnings) == 1


def test_the_fold_says_nothing_for_a_document_in_the_canonical_spelling() -> None:
    document = _suppressions(_entry(expires="2099-01-01"))

    folded = spellings.fold_spellings(document, SOURCE)

    assert folded.document == document
    assert folded.warnings == ()


def test_the_fold_drops_an_old_spelling_equal_to_the_canonical_one() -> None:
    folded = spellings.fold_spellings(
        _suppressions(_entry(expires="2099-01-01", expiration="2099-01-01")), SOURCE
    )

    (entry,) = folded.document["global_settings"]["suppressions"]
    assert "expiration" not in entry
    assert entry["expires"] == "2099-01-01"


def test_the_fold_refuses_a_disagreement_naming_the_place_and_no_value() -> None:
    with pytest.raises(spellings.SpellingRefused) as refused:
        spellings.fold_spellings(
            _suppressions(_entry(expires="2099-01-01", expiration="2098-12-31")),
            SOURCE,
        )

    message = str(refused.value)
    assert SOURCE in message
    assert "global_settings.suppressions[0]" in message
    assert "expires" in message
    assert "expiration" in message
    # The values can be read from the environment: never printed.
    assert "2099" not in message
    assert "2098" not in message


def test_the_fold_refuses_the_old_spelling_at_its_removal_release() -> None:
    with pytest.raises(spellings.SpellingRefused) as refused:
        spellings.fold_spellings(
            _suppressions(_entry(expiration="2099-01-01")), SOURCE, version="4.0.0"
        )

    message = str(refused.value)
    assert SOURCE in message
    assert "'expires'" in message


def test_the_fold_reaches_a_scanners_options_list() -> None:
    document = {
        "scanners": {
            "bandit": {
                "options": {
                    "excluded_paths": [
                        {"path": "tests/", "reason": "r", "expiration": "2099-01-01"}
                    ]
                }
            }
        }
    }

    folded = spellings.fold_spellings(document, SOURCE)

    (entry,) = folded.document["scanners"]["bandit"]["options"]["excluded_paths"]
    assert entry == {"path": "tests/", "reason": "r", "expires": "2099-01-01"}


def test_the_fold_leaves_a_staleness_overrides_own_expiration_key() -> None:
    document = {
        "content_db_staleness_overrides": [
            {
                "database": "grype-db",
                "policy": "warn",
                "expiration": "2099-01-01",
                "reason": "upstream paused",
            }
        ]
    }

    folded = spellings.fold_spellings(document, SOURCE)

    assert folded.document == document
    assert folded.warnings == ()


def test_the_folds_line_names_the_file_as_given_for_its_sink_to_show_once() -> None:
    """A resolution warning's sink (core/orchestrator.py) shows the whole line,
    as config_sources.describe_config_path says every message is shown: a name
    the fold had escaped first would be shown twice, its backslash doubled."""
    source = "cfg" + ESCAPE + "[31m.yaml"

    folded = spellings.fold_spellings(
        _suppressions(_entry(expiration="2099-01-01")), source
    )

    assert folded.warnings == (f"Config {source}: {EXPIRATION_SPELLING_DEPRECATION}",)
    (shown,) = [shown_on_one_line(line) for line in folded.warnings]
    assert "cfg" + BACKSLASH + "x1b[31m.yaml" in shown
    assert BACKSLASH * 2 not in shown


def test_the_folds_refusal_names_the_file_as_given() -> None:
    source = "cfg" + RIGHT_TO_LEFT_OVERRIDE + "lmay.yaml"

    with pytest.raises(spellings.SpellingRefused) as refused:
        spellings.fold_spellings(
            _suppressions(_entry(expires="2099-01-01", expiration="2098-12-31")),
            source,
        )

    assert str(refused.value).startswith(f"Config {source}: ")


def _patching(*ops: Dict[str, Any]) -> Dict[str, Any]:
    return {"patch": list(ops)}


def test_the_fold_respells_a_patch_pointer_along_the_model() -> None:
    folded = spellings.fold_spellings(
        _patching(
            {
                "op": "move",
                "from": "/global_settings/suppressions/0/expiration",
                "path": "/global_settings/suppressions/1/expiration",
            }
        ),
        SOURCE,
    )

    (op,) = folded.document["patch"]
    assert op["from"] == "/global_settings/suppressions/0/expires"
    assert op["path"] == "/global_settings/suppressions/1/expires"
    assert folded.warnings == (f"Config {SOURCE}: {EXPIRATION_SPELLING_DEPRECATION}",)


@pytest.mark.parametrize(
    "path",
    [
        # canonical in its own model
        "/content_db_staleness_overrides/0/expiration",
        # a key the model does not declare is not walked
        "/not_a_setting/0/expiration",
    ],
)
def test_the_fold_leaves_a_pointer_the_table_does_not_name(path: str) -> None:
    document = _patching({"op": "replace", "path": path, "value": "2099-01-01"})

    folded = spellings.fold_spellings(document, SOURCE)

    assert folded.document == document
    assert folded.warnings == ()


@pytest.mark.parametrize(
    "path,value",
    [
        ("/global_settings/suppressions/-", _entry(expiration="2099-01-01")),
        ("/global_settings/suppressions/0", _entry(expiration="2099-01-01")),
        ("/global_settings/suppressions", [_entry(expiration="2099-01-01")]),
        (
            "/global_settings",
            {"suppressions": [_entry(expiration="2099-01-01")]},
        ),
    ],
    ids=["append", "index", "list", "mapping"],
)
def test_the_fold_reads_an_ops_value_as_the_model_its_path_names(
    path: str, value: Any
) -> None:
    folded = spellings.fold_spellings(
        _patching({"op": "add", "path": path, "value": value}), SOURCE
    )

    (op,) = folded.document["patch"]
    assert "expiration" not in repr(op["value"])
    assert "'expires': '2099-01-01'" in repr(op["value"])
    assert len(folded.warnings) == 1


def test_the_fold_refuses_an_ops_value_with_disagreeing_spellings() -> None:
    with pytest.raises(spellings.SpellingRefused) as refused:
        spellings.fold_spellings(
            _patching(
                {
                    "op": "add",
                    "path": "/global_settings/suppressions/-",
                    "value": _entry(expires="2099-01-01", expiration="2098-12-31"),
                }
            ),
            SOURCE,
        )

    message = str(refused.value)
    assert SOURCE in message
    assert "patch[0]" in message
    assert "2099" not in message
    assert "2098" not in message


@pytest.mark.parametrize(
    "op",
    [
        {
            "op": "replace",
            "path": "/global_settings/suppressions/0/expiration",
            "value": "2099-01-01",
        },
        {
            "op": "add",
            "path": "/global_settings/suppressions/-",
            "value": _entry(expiration="2099-01-01"),
        },
    ],
    ids=["pointer", "value"],
)
def test_a_removed_rows_old_spelling_is_refused_in_a_patch_op(
    op: Dict[str, Any],
) -> None:
    with pytest.raises(spellings.SpellingRefused) as refused:
        spellings.fold_spellings(_patching(op), SOURCE, version="4.0.0")

    message = str(refused.value)
    assert SOURCE in message
    assert "patch[0]" in message
    assert "'expiration'" in message
    assert "'expires'" in message


def test_the_written_view_respells_a_patch_op_alike() -> None:
    """The as-written ops pair with the folded ones: same pointers, same keys."""
    written = spellings.fold_written_spellings(
        _patching(
            {
                "op": "add",
                "path": "/global_settings/suppressions/0/expiration",
                "value": "${EXPIRY}",
            },
            {
                "op": "add",
                "path": "/global_settings/suppressions/-",
                "value": _entry(expiration="${EXPIRY}"),
            },
        )
    )

    first, second = written["patch"]
    assert first["path"] == "/global_settings/suppressions/0/expires"
    assert second["value"] == _entry(expires="${EXPIRY}")


def test_the_written_view_is_folded_alike_with_no_line_and_no_refusal() -> None:
    """The as-written copy of a file (its environment references) must pair
    with the folded data key for key, and is never where a refusal is made."""
    renamed = spellings.fold_written_spellings(
        _suppressions(_entry(expiration="${EXPIRY}"))
    )
    both = spellings.fold_written_spellings(
        _suppressions(_entry(expires="${A}", expiration="${B}"))
    )

    assert renamed == _suppressions(_entry(expires="${EXPIRY}"))
    assert both == _suppressions(_entry(expires="${A}"))


# ---------------------------------------------------------------------------
# check_spellings: a model built without the loader
# ---------------------------------------------------------------------------


def test_a_stored_entry_keeps_a_disagreement_as_a_note_at_any_release(
    monkeypatch,
) -> None:
    monkeypatch.setattr(automated_security_helper, "__version__", "4.0.0")
    notes: List[str] = []

    entry = AshSuppression.model_validate(
        _entry(expires="2099-12-31", expiration="2026-01-01"),
        context={TOLERATE_STORED_CONFIG: notes},
    )

    assert notes
    assert entry.has_unknown_keys


def test_the_root_model_applies_the_rule_for_a_row_of_its_own(monkeypatch) -> None:
    """A top-level row, as a later change adds one: refused when the spellings
    disagree."""
    _with_row(
        monkeypatch,
        model=ROOT,
        canonical="mcp_resource_management",
        old=("mcp-resource-management",),
    )

    with pytest.raises(ValidationError) as refused:
        AshConfig.model_validate(
            {
                "mcp_resource_management": {"max_concurrent_scans": 2},
                "mcp-resource-management": {"max_concurrent_scans": 9},
            }
        )
    assert "mcp-resource-management" in str(refused.value)

    agreed = AshConfig.model_validate(
        {
            "mcp_resource_management": {"max_concurrent_scans": 2},
            "mcp-resource-management": {"max_concurrent_scans": 2},
        }
    )
    assert agreed.mcp_resource_management.max_concurrent_scans == 2


# ---------------------------------------------------------------------------
# A row added to the table reaches the loader, the merge and lint
# ---------------------------------------------------------------------------


_IGNORED = {"path": "build/", "reason": "generated"}


@pytest.fixture
def renamed_global_settings(monkeypatch) -> spellings.SpellingRow:
    """A mapping-valued setting renamed to a spelling that is no '-'/'_' twin."""
    return _with_row(
        monkeypatch, model=ROOT, canonical="global_settings", old=("settings_global",)
    )


def test_a_child_in_the_canonical_spelling_merges_over_a_base_in_the_old_one(
    tmp_path: Path, renamed_global_settings
) -> None:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {"settings_global": {"severity_threshold": "LOW", "ignore_paths": [_IGNORED]}},
    )
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {"extends": "org.yaml", "global_settings": {"severity_threshold": "HIGH"}},
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.severity_threshold == "HIGH"
    # The base's other setting is merged, not dropped with its spelling.
    assert [p.path for p in config.global_settings.ignore_paths] == ["build/"]


def test_a_child_in_the_old_spelling_merges_over_a_base_in_the_canonical_one(
    tmp_path: Path, renamed_global_settings
) -> None:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {"global_settings": {"severity_threshold": "LOW", "ignore_paths": [_IGNORED]}},
    )
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {"extends": "org.yaml", "settings_global": {"severity_threshold": "HIGH"}},
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.severity_threshold == "HIGH"
    assert [p.path for p in config.global_settings.ignore_paths] == ["build/"]


def test_a_patch_pointer_in_the_old_spelling_reaches_the_merged_setting(
    tmp_path: Path, renamed_global_settings
) -> None:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {"global_settings": {"severity_threshold": "LOW"}},
    )
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {
            "extends": "org.yaml",
            "patch": [
                {
                    "op": "replace",
                    "path": "/settings_global/severity_threshold",
                    "value": "HIGH",
                }
            ],
        },
    )

    assert AshConfig.from_file(child).global_settings.severity_threshold == "HIGH"


@pytest.fixture
def renamed_root_key(monkeypatch) -> spellings.SpellingRow:
    """A top-level row, ahead of the field change that declares it through the
    table."""
    return _with_row(
        monkeypatch,
        model=ROOT,
        canonical="mcp_resource_management",
        old=("mcp-resource-management",),
    )


def _lint_file(tmp_path: Path, document: Dict[str, Any]) -> Path:
    return _write(tmp_path / ".ash.yaml", document)


def test_lint_reports_a_rows_old_root_spelling_as_fixable(
    tmp_path: Path, renamed_root_key
) -> None:
    config = _lint_file(
        tmp_path, {"mcp-resource-management": {"max_concurrent_scans": 3}}
    )

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues

    variants = [i for i in issues if i.category == LintCategory.LEGACY_NAME_VARIANT]
    assert [i.path for i in variants] == ["mcp-resource-management"]
    assert variants[0].fixable is True
    assert variants[0].fix_description


def test_lint_fix_renames_a_rows_old_root_spelling(
    tmp_path: Path, renamed_root_key
) -> None:
    config = _lint_file(
        tmp_path, {"mcp-resource-management": {"max_concurrent_scans": 3}}
    )

    fixed_content, fixed_issues = ConfigLinter.fix(config)

    data = yaml.safe_load(
        "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
    )
    assert "mcp-resource-management" not in data
    assert data["mcp_resource_management"] == {"max_concurrent_scans": 3}
    assert any(i.category == LintCategory.LEGACY_NAME_VARIANT for i in fixed_issues)


def test_lint_leaves_a_rows_canonical_root_spelling_alone(
    tmp_path: Path, renamed_root_key
) -> None:
    config = _lint_file(
        tmp_path, {"mcp_resource_management": {"max_concurrent_scans": 3}}
    )

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues

    assert [i for i in issues if i.category == LintCategory.LEGACY_NAME_VARIANT] == []


def test_a_written_config_does_not_keep_a_rows_old_spelling_as_an_unknown_key(
    tmp_path: Path, monkeypatch
) -> None:
    """A rewrite keeps top-level keys the model does not read, and an old
    spelling of a field it writes is not one of them."""
    from automated_security_helper.config.config_writer import render_config_file

    _with_row(monkeypatch, model=ROOT, canonical="project_name", old=("projectname",))

    text = render_config_file(
        tmp_path / ".ash.yaml",
        AshConfig(project_name="renamed"),
        [],
        keep_from={"projectname": "renamed", "$schema": "kept"},
    )

    written = yaml.safe_load(text)
    assert "projectname" not in written
    assert written["$schema"] == "kept"


# ---------------------------------------------------------------------------
# A row added to the table reaches the places that find a denial, and not the
# places that skip a check or grant an exemption
# ---------------------------------------------------------------------------


GLOBAL_SETTINGS = (
    "automated_security_helper.config.ash_config.AshConfigGlobalSettingsSection"
)
OPENGREP_OPTIONS = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner"
    ".OpengrepScannerConfigOptions"
)
PACKS_MODEL = (
    "automated_security_helper.plugin_modules.ash_builtin.scanners."
    "cdk_nag_scanner.CdkNagPacks"
)


def _profile_with_policy(**runtime_overrides: Any) -> AshConfig:
    """A profile whose runtime-override policy is ``runtime_overrides``."""
    return AshConfig.model_validate(
        {"global_settings": {"mcp": {"runtime_overrides": runtime_overrides}}}
    )


@pytest.fixture
def renamed_severity_threshold(monkeypatch) -> spellings.SpellingRow:
    """A field of a section renamed to a spelling that is no '-'/'_' twin."""
    return _with_row(
        monkeypatch,
        model=GLOBAL_SETTINGS,
        canonical="severity_threshold",
        old=("severity_floor",),
    )


def test_a_value_pattern_refuses_a_mapping_key_in_a_rows_old_spelling(
    monkeypatch,
) -> None:
    """A value pattern applies to a mapping key a document writes when the
    pattern's subtree holds the key's pointer (``_key_pattern_reason``). A
    pattern bound to the canonical pointer holds the field under every spelling
    the table gives it, so a key written in the old spelling is refused by it.
    Without the row the key names no field the pattern holds, and nothing is
    refused.

    What turns this red: ``_key_pattern_reason``'s ``_covered`` call without
    ``denying=True``, which never meets ``severity_floor``.
    """
    from automated_security_helper.config.client_config_policy import policy_of
    from automated_security_helper.config.runtime_patch import (
        config_document_denials,
    )

    trusted = _profile_with_policy(
        denied_value_patterns={
            "/global_settings/severity_threshold": "^severity_floor$"
        }
    )
    document = {"global_settings": {"severity_floor": "HIGH"}}

    def reasons() -> List[str]:
        return [
            denial.reason
            for denial in config_document_denials(
                document, allowlist=policy_of(trusted), config=trusted
            )
        ]

    assert reasons() == []

    _with_row(
        monkeypatch,
        model=GLOBAL_SETTINGS,
        canonical="severity_threshold",
        old=("severity_floor",),
    )

    # The key's write only: the leaf's value does not match the regex.
    assert reasons() == [
        (
            "key 'severity_floor' at '/global_settings/severity_floor' matches "
            "denied_value_patterns regex '^severity_floor$' bound to "
            "'/global_settings/severity_threshold'"
        )
    ]


def test_an_old_spelling_denial_takes_its_field_out_of_the_exempt_set(
    monkeypatch,
) -> None:
    """A delivered file is not checked against ``denied_paths`` for the
    restrict-only and suppression fields unless the operator's own list names
    one; then it is checked against that list for the whole field
    (``client_config_policy.exempt_paths``). Whether an entry names a field is
    decided through ``runtime_patch._denied_path_reason``, a place that finds a
    denial, so an entry written in a row's old spelling takes its field out of
    the exempt set. Without the row the entry names nothing, and every field
    stays exempt.

    What turns this red: ``_denied_path_reason`` matching over
    ``_denial_spellings`` alone, which leaves ``/sandbox`` exempt.
    """
    from automated_security_helper.config.client_config_policy import (
        exempt_paths,
        policy_of,
    )

    policy = policy_of(_profile_with_policy(denied_paths=["/scan_sandbox"]))

    assert "/sandbox" in exempt_paths(policy)

    _with_row(monkeypatch, model=ROOT, canonical="sandbox", old=("scan_sandbox",))

    exempt = exempt_paths(policy)
    assert "/sandbox" not in exempt
    assert "/sandbox/**" not in exempt
    # Only the field the entry names leaves the set.
    assert "/ash_plugin_modules" in exempt
    assert "/global_settings/suppressions" in exempt


def test_a_moved_exclusion_does_not_lift_the_floor_for_a_rows_old_spelling(
    monkeypatch,
) -> None:
    """Resolution moves a delivered scanner exclusion out of the scanner's
    options, so ``config_document_denials`` does not let the always-denied entry
    that covers the scanner's whole section (``SECTION_FLOOR_ENTRIES``) refuse a
    leaf at or under a moved pointer. That lifts a refusal, so it matches a
    pointer as written and with '-' read as '_'. ``moved_exclusion_pointers``
    names an option under its own name, so the same file's list under the
    option's old spelling is not moved, and the floor still refuses it. Without
    the row the outcome is the same: the row is what a widened match would read.

    What turns this red: the moved check's ``_covered`` call matched with the
    table's spellings, which reads ``skip_globs`` as the moved ``exclude`` and
    lifts the floor for it, so nothing refuses it.
    """
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.client_scanner_exclusions import (
        moved_exclusion_pointers,
    )
    from automated_security_helper.config.runtime_patch import (
        SECTION_FLOOR_ENTRIES,
        config_document_denials,
    )

    _with_row(
        monkeypatch, model=OPENGREP_OPTIONS, canonical="exclude", old=("skip_globs",)
    )
    document = {
        "scanners": {
            "opengrep": {
                "options": {"exclude": ["build/**"], "skip_globs": ["vendor/**"]}
            }
        }
    }
    moved = moved_exclusion_pointers(document)
    # The premises: the move names the option under its own spelling only, and
    # the entry that refuses the old one is a section floor.
    assert moved == ["/scanners/opengrep/options/exclude"]
    assert "/scanners/opengrep/**" in SECTION_FLOOR_ENTRIES

    denials = config_document_denials(
        document, allowlist=RuntimeOverridesConfig(), config=AshConfig(), moved=moved
    )

    assert [(d.pointer, d.from_patch) for d in denials] == [
        ("/scanners/opengrep/options/skip_globs", False)
    ]
    assert "denied_paths entry '/scanners/opengrep/**'" in denials[0].reason


@pytest.mark.parametrize(
    "recorded,own",
    [
        pytest.param(
            "/global_settings/severity_threshold",
            "/global_settings/severity_floor",
            id="recorded-canonical-own-old",
        ),
        pytest.param(
            "/global_settings/severity_floor",
            "/global_settings/severity_threshold",
            id="recorded-old-own-canonical",
        ),
    ],
)
def test_a_recorded_reference_and_the_copys_own_are_two_places_across_a_rename(
    recorded: str, own: str, renamed_severity_threshold
) -> None:
    """``_holds_the_operators_reference`` lets a client-patched copy of the
    profile repeat a leaf the trusted config read from the environment only
    where the copy holds the operator's own reference, at the one place the
    trusted config's files wrote it. That grants an exemption, so places are
    compared as written and with '-' read as '_' (``_same_place``): a text
    recorded under one spelling of a renamed field and the copy's reference
    under the other are two places, and the leaf is not the operator's
    reference.

    What turns this red: ``_same_place`` matching with the table's spellings,
    which makes the two spellings one place. Respelling only the copy's pointer
    turns the first case red, only the recorded one the second.
    """
    from automated_security_helper.config.runtime_patch import (
        _holds_the_operators_reference,
        known_plugin_keys,
    )

    text = "${ASH_TEST_SEVERITY}"
    keys = known_plugin_keys(None)

    # The control: one place, one text, held as the operator's own.
    assert _holds_the_operators_reference(
        recorded, {recorded: (text,)}, {recorded: {text}}, keys
    )

    assert not _holds_the_operators_reference(
        own, {recorded: (text,)}, {own: {text}}, keys
    )


# ---------------------------------------------------------------------------
# A row on a section's model, or on a plugin's options, reaches lint
# ---------------------------------------------------------------------------


@pytest.fixture
def renamed_pack_key(monkeypatch) -> spellings.SpellingRow:
    """A field of a plugin's options model, as a pack's rename declares one."""
    return _with_row(
        monkeypatch,
        model=PACKS_MODEL,
        canonical="AwsSolutionsChecks",
        old=("aws_solutions_checks",),
    )


def _data_of(fixed_content: str) -> Dict[str, Any]:
    return yaml.safe_load(
        "\n".join(
            line for line in fixed_content.split("\n") if not line.startswith("#")
        )
    )


def _of(issues: List[Any], category: LintCategory) -> List[Any]:
    return [i for i in issues if i.category == category]


def test_lint_reports_a_rows_old_spelling_in_a_section_where_the_file_writes_it(
    tmp_path: Path, renamed_severity_threshold
) -> None:
    config = _lint_file(
        tmp_path,
        {"global_settings": {"severity_floor": "HIGH", "ignore_paths": [_IGNORED]}},
    )

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues

    (variant,) = _of(issues, LintCategory.LEGACY_NAME_VARIANT)
    assert variant.path == "global_settings.severity_floor"
    assert variant.fixable is True
    assert variant.fix_description
    assert "severity_floor" in variant.message
    assert "severity_threshold" in variant.message


def test_lint_fix_renames_a_rows_old_spelling_in_a_section_in_place(
    tmp_path: Path, renamed_severity_threshold
) -> None:
    config = _lint_file(
        tmp_path,
        {"global_settings": {"severity_floor": "HIGH", "ignore_paths": [_IGNORED]}},
    )

    fixed_content, fixed_issues = ConfigLinter.fix(config)

    settings = _data_of(fixed_content)["global_settings"]
    assert list(settings) == ["severity_threshold", "ignore_paths"]
    assert settings["severity_threshold"] == "HIGH"
    assert [i.path for i in _of(fixed_issues, LintCategory.LEGACY_NAME_VARIANT)] == [
        "global_settings.severity_floor"
    ]


def test_lint_reports_both_spellings_in_a_section_as_a_conflict_it_leaves(
    tmp_path: Path, renamed_severity_threshold
) -> None:
    """A rename here would drop one of the two values, so --fix leaves both."""
    both = {"severity_floor": "HIGH", "severity_threshold": "LOW"}
    config = _lint_file(tmp_path, {"global_settings": dict(both)})

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues
    fixed_content, _ = ConfigLinter.fix(config)

    (conflict,) = _of(issues, LintCategory.LEGACY_NAME_CONFLICT)
    assert conflict.path == "global_settings.severity_floor"
    assert conflict.fixable is False
    assert _of(issues, LintCategory.LEGACY_NAME_VARIANT) == []
    assert _data_of(fixed_content)["global_settings"] == both


def test_lint_leaves_a_rows_canonical_spelling_in_a_section_alone(
    tmp_path: Path, renamed_severity_threshold
) -> None:
    config = _lint_file(tmp_path, {"global_settings": {"severity_threshold": "HIGH"}})

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues

    assert _of(issues, LintCategory.LEGACY_NAME_VARIANT) == []
    assert _of(issues, LintCategory.LEGACY_NAME_CONFLICT) == []


def test_lint_reports_and_fixes_a_rows_old_spelling_inside_a_plugins_options(
    tmp_path: Path, renamed_pack_key
) -> None:
    """A row on a model a plugin's options hold is reported, and renamed, where
    the file writes it, under the plugin's name as the file spells it."""
    config = _lint_file(
        tmp_path,
        {
            "scanners": {
                "cdk-nag": {"options": {"nag_packs": {"aws_solutions_checks": True}}}
            }
        },
    )

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues
    fixed_content, _ = ConfigLinter.fix(config)

    (variant,) = _of(issues, LintCategory.LEGACY_NAME_VARIANT)
    assert variant.path == "scanners.cdk-nag.options.nag_packs.aws_solutions_checks"
    assert variant.fixable is True
    packs = _data_of(fixed_content)["scanners"]["cdk-nag"]["options"]["nag_packs"]
    assert packs == {"AwsSolutionsChecks": True}


def test_an_entry_rows_old_spelling_stays_a_deprecated_spelling(
    tmp_path: Path,
) -> None:
    """The entry model's rows have their own issue, which says why it is no fix
    lint makes; the section rows' check leaves them to it."""
    config = _lint_file(tmp_path, _suppressions(_entry(expiration="2099-01-01")))

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues

    assert len(_of(issues, LintCategory.DEPRECATED_SPELLING)) == 1
    assert _of(issues, LintCategory.LEGACY_NAME_VARIANT) == []
