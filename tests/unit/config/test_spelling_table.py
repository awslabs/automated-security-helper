"""The spelling table: one row per renamed configuration key, read by every reader.

A row names the model whose field was renamed, the canonical spelling (the
field name), the old spellings the loader still reads, the release that
introduced the canonical spelling and the release that stops accepting the old
ones. The models declare a renamed field through ``renamed_field``; the loader
folds each file's old spellings through ``fold_spellings``; the models apply the
both-spellings rule through ``check_spellings`` when they are built without the
loader; lint, patch pointers and the runtime-patch denials read the same rows.

These tests pin the table's contract, and they pin it on a row a test adds as
well as on the shipped one, because a shipped mapping-valued or top-level row
is the next unit's: a row added to the table must reach every reader with no
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
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

ROOT = "automated_security_helper.config.ash_config.AshConfig"
ENTRY_MODEL = "automated_security_helper.models.core.IgnorePathWithReason"
SOURCE = "cfg.yaml"


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


def test_at_the_running_version_the_old_spelling_loads_until_its_removal() -> None:
    """Fails the day the version reaches a row's release while the model still
    reads its old spelling, or before that day if the model stops early."""
    entry = _entry(expiration="2099-01-01")
    if spellings.is_removed(_expires_row()):
        with pytest.raises(ValidationError):
            AshSuppression.model_validate(entry)
    else:
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
    """The next unit's top-level row: refused when the spellings disagree."""
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
    """The next unit's row, ahead of its field change."""
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
