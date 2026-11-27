"""An old spelling of a renamed key loads until the release that removes it.

``expiration``, the earlier spelling of ``expires``, loads with a deprecation
line through 3.x, and from 4.0 on a document the loader reads that writes it is
refused, naming the canonical spelling. The running version decides, so the 4.0
release refuses it with no edit to the models. The models read the old spelling
at every release: an entry built outside the loader, and a results file a scan
already wrote, keep loading, and a stored record keeps applying.

A ``patch`` op is part of its file: a pointer or an op's value that names the
old spelling is refused at 4.0 as a key is, naming the file. A refusal ends with
the sentence the command registry gives, which names the command that rewrites
the file once one is registered.

Red at the base: at 4.0 a config, a base it extends and an op's value all still
loaded the old spelling, and a pointer in it failed to apply without naming
either spelling.
"""

import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

import automated_security_helper
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.unknown_keys import (
    TOLERATE_STORED_CONFIG,
    WARN_UNKNOWN_KEYS,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

REMOVAL_RELEASE = "4.0.0"

#: The refusal of the old spelling at the removal release, before any sentence.
REMOVAL = "The 'expiration' key is no longer read as of ASH 4.0; write 'expires'."

#: The command a test registers as the one that rewrites a config file, and the
#: sentences the registry then gives.
UPGRADE_SENTINEL = "ash-registry-sentinel upgrade"
REWRITE_SENTENCE = " Run ash-registry-sentinel upgrade to rewrite this file."
BY_HAND_SENTENCE = (
    " Edit this key by hand: ash-registry-sentinel upgrade prints the edit."
)

_ENTRY = {"rule_id": "B101", "path": "src/app.py", "reason": "reviewed"}


@pytest.fixture
def running(monkeypatch):
    """Set the version ASH reports while the test runs."""

    def _set(version: str) -> None:
        monkeypatch.setattr(automated_security_helper, "__version__", version)

    return _set


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _old_spelling_document() -> Dict[str, Any]:
    return {
        "global_settings": {
            "suppressions": [{**_ENTRY, "expiration": "2099-01-01"}],
        }
    }


def test_a_config_writing_the_old_spelling_is_refused_at_the_removal_release(
    tmp_path: Path, running
) -> None:
    running(REMOVAL_RELEASE)
    config = _write(tmp_path / "cfg" / "only.yaml", _old_spelling_document())

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(config)

    message = str(refused.value)
    assert "only.yaml" in message
    assert "'expiration'" in message
    assert "'expires'" in message


def test_a_base_writing_the_old_spelling_is_refused_naming_the_base(
    tmp_path: Path, running
) -> None:
    running(REMOVAL_RELEASE)
    _write(tmp_path / "cfg" / "org.yaml", _old_spelling_document())
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {"extends": "org.yaml", "fail_on_findings": False},
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "org.yaml" in message
    assert "'expiration'" in message
    assert "'expires'" in message


def _child_patching(tmp_path: Path, ops: Any) -> Path:
    """A file whose ``patch`` ops run over a base written in the new spelling."""
    _write(
        tmp_path / "cfg" / "org.yaml",
        {"global_settings": {"suppressions": [{**_ENTRY, "expires": "2099-01-01"}]}},
    )
    return _write(tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml", "patch": ops})


def test_a_patch_pointer_in_the_old_spelling_is_refused_at_the_removal_release(
    tmp_path: Path, running
) -> None:
    running(REMOVAL_RELEASE)
    child = _child_patching(
        tmp_path,
        [
            {
                "op": "replace",
                "path": "/global_settings/suppressions/0/expiration",
                "value": "2199-12-31",
            }
        ],
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "repo.yaml" in message
    assert "'expiration'" in message
    assert "'expires'" in message


def test_a_patch_ops_value_in_the_old_spelling_is_refused_at_the_removal_release(
    tmp_path: Path, running
) -> None:
    running(REMOVAL_RELEASE)
    child = _child_patching(
        tmp_path,
        [
            {
                "op": "add",
                "path": "/global_settings/suppressions/-",
                "value": {**_ENTRY, "path": "src/other.py", "expiration": "2099-02-02"},
            }
        ],
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "repo.yaml" in message
    # Refused by the file's fold, which names the op, not by the entry model.
    assert "patch[0]" in message
    assert "'expiration'" in message
    assert "'expires'" in message


def test_a_root_ops_value_in_the_old_spelling_is_refused_at_the_removal_release(
    tmp_path: Path, running
) -> None:
    """The root pointer names the whole document, so an op's value there is read
    as the whole configuration and its old spelling is refused naming the op."""
    running(REMOVAL_RELEASE)
    child = _child_patching(
        tmp_path,
        [
            {
                "op": "replace",
                "path": "",
                "value": _old_spelling_document(),
            }
        ],
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "repo.yaml" in message
    assert "patch[0]" in message
    assert "'expiration'" in message
    assert "'expires'" in message


def test_an_entry_validated_outside_the_loader_loads_at_the_removal_release(
    running,
) -> None:
    """The model reads a removed spelling as the canonical key; what refuses it is
    the loader's read of a document."""
    running(REMOVAL_RELEASE)

    entry = AshSuppression.model_validate({**_ENTRY, "expiration": "2099-01-01"})

    assert entry.expires == "2099-01-01"
    assert not entry.has_unknown_keys


@pytest.mark.parametrize("bound", ["none", "warn-list", "stored-record"])
def test_an_entry_validated_outside_the_loader_says_nothing_at_the_removal_release(
    running, bound: str
) -> None:
    """At the removal release the model renames the old key silently in every
    validation context: no warning, and no line in a list the context binds."""
    running(REMOVAL_RELEASE)
    lines: List[str] = []
    context: Optional[Dict[str, Any]] = {
        "none": None,
        "warn-list": {WARN_UNKNOWN_KEYS: lines},
        "stored-record": {TOLERATE_STORED_CONFIG: lines},
    }[bound]

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        entry = AshSuppression.model_validate(
            {**_ENTRY, "expiration": "2099-01-01"}, context=context
        )

    assert entry.expires == "2099-01-01"
    assert not entry.has_unknown_keys
    assert [str(w.message) for w in caught if "'expiration'" in str(w.message)] == []
    assert lines == []


def test_an_entry_validated_outside_the_loader_says_the_deprecation_while_live(
    running,
) -> None:
    """The control: one release before the removal the model says the
    deprecation, as it always has."""
    running("3.99.0")

    with pytest.warns(DeprecationWarning, match="deprecated spelling of 'expires'"):
        entry = AshSuppression.model_validate({**_ENTRY, "expiration": "2099-01-01"})

    assert entry.expires == "2099-01-01"


def test_a_stored_results_entry_keeps_loading_at_the_removal_release(
    running,
) -> None:
    """A results file is a record of its run: it is read, never refused."""
    running(REMOVAL_RELEASE)

    entry = AshSuppression.model_validate(
        {**_ENTRY, "expiration": "2099-01-01"},
        context={TOLERATE_STORED_CONFIG: []},
    )

    assert entry.expires == "2099-01-01"


def _finding() -> FlatVulnerability:
    """A finding the suppression ``_ENTRY`` covers."""
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="bandit",
        scanner_type="SAST",
        rule_id="B101",
        file_path="src/app.py",
    )


def test_a_371_shaped_stored_config_keeps_applying_at_the_removal_release(
    running,
) -> None:
    """A config 3.7.1 stored spells every entry's expiry ``expiration``, a null one
    included; at the removal release each entry keeps its expiry and applies."""
    from automated_security_helper.config import spellings

    running(REMOVAL_RELEASE)
    (row,) = [r for r in spellings.ROWS if r.canonical == "expires"]
    assert row.status() == "removed"
    stored = {
        "project_name": "stored",
        "global_settings": {
            "suppressions": [{**_ENTRY, "expiration": "2099-01-01"}],
            "ignore_paths": [
                {"path": "build/", "reason": "generated", "expiration": None}
            ],
        },
    }
    notes: List[str] = []

    config = AshConfig.model_validate(stored, context={TOLERATE_STORED_CONFIG: notes})

    assert notes == []
    (suppression,) = config.global_settings.suppressions
    assert suppression.expires == "2099-01-01"
    assert not suppression.has_unknown_keys
    assert suppression.matches(_finding())
    (ignored,) = config.global_settings.ignore_paths
    assert ignored.expires is None
    assert not ignored.has_unknown_keys


def test_a_release_before_the_removal_loads_the_old_spelling(
    tmp_path: Path, running
) -> None:
    """The control: one release earlier, the same file loads as it always has."""
    running("3.99.0")
    config = _write(tmp_path / "cfg" / "only.yaml", _old_spelling_document())

    loaded = AshConfig.from_file(config)

    assert loaded.global_settings.suppressions[0].expires == "2099-01-01"


def test_the_canonical_spelling_loads_at_the_removal_release(
    tmp_path: Path, running
) -> None:
    """The control: only the old spelling is refused at the removal release."""
    running(REMOVAL_RELEASE)
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        {"global_settings": {"suppressions": [{**_ENTRY, "expires": "2099-01-01"}]}},
    )

    loaded = AshConfig.from_file(config)

    assert loaded.global_settings.suppressions[0].expires == "2099-01-01"


def test_a_removed_rows_refusal_names_no_command_while_none_is_registered(
    tmp_path: Path, running, monkeypatch
) -> None:
    """While the registry holds no command that rewrites a file, a refusal at the
    removal release carries the removal message and no command sentence."""
    from automated_security_helper.config import spellings
    from automated_security_helper.core import command_names

    monkeypatch.setattr(command_names, "CONFIG_UPGRADE", None, raising=False)
    running(REMOVAL_RELEASE)
    config = _write(tmp_path / "cfg" / "only.yaml", _old_spelling_document())

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(config)

    message = str(refused.value)
    assert REMOVAL in message
    assert "rewrite this file" not in message
    assert "Edit this key by hand" not in message
    (row,) = [r for r in spellings.ROWS if r.canonical == "expires"]
    assert spellings.removal_message(row, "expiration") == REMOVAL


_YAML_OLD_SPELLING = yaml.safe_dump(_old_spelling_document(), sort_keys=False)

_TOML_OLD_SPELLING = """[[global_settings.suppressions]]
rule_id = "B101"
path = "src/app.py"
reason = "reviewed"
expiration = "2099-01-01"
"""


@pytest.mark.parametrize(
    "name,text,sentence,other",
    [
        ("only.yaml", _YAML_OLD_SPELLING, REWRITE_SENTENCE, BY_HAND_SENTENCE),
        ("only.toml", _TOML_OLD_SPELLING, BY_HAND_SENTENCE, REWRITE_SENTENCE),
    ],
    ids=["yaml", "toml"],
)
def test_a_removed_rows_refusal_takes_its_command_sentence_from_the_registry(
    tmp_path: Path,
    running,
    monkeypatch,
    name: str,
    text: str,
    sentence: str,
    other: str,
) -> None:
    """Once the registry holds the command, a refusal at the removal release ends
    with its sentence: run it for a YAML file, edit by hand for a TOML one."""
    from automated_security_helper.core import command_names

    monkeypatch.setattr(
        command_names, "CONFIG_UPGRADE", command_names.Command(text=UPGRADE_SENTINEL)
    )
    running(REMOVAL_RELEASE)
    config = tmp_path / "cfg" / name
    config.parent.mkdir(parents=True)
    config.write_text(text, encoding="utf-8")

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(config)

    message = str(refused.value)
    assert REMOVAL + sentence in message
    assert other not in message


def test_the_removal_message_ends_with_the_registrys_sentence(monkeypatch) -> None:
    """The message builder reads the registry when it runs: no sentence while no
    command is registered, and the registered command's sentence once one is."""
    from automated_security_helper.config import spellings
    from automated_security_helper.core import command_names

    (row,) = [r for r in spellings.ROWS if r.canonical == "expires"]

    monkeypatch.setattr(command_names, "CONFIG_UPGRADE", None)
    assert command_names.rewrite_sentence() == ""
    assert command_names.rewrite_sentence(by_hand=True) == ""
    assert spellings.removal_message(row, "expiration") == REMOVAL
    assert spellings.removal_message(row, "expiration", by_hand=True) == REMOVAL

    monkeypatch.setattr(
        command_names, "CONFIG_UPGRADE", command_names.Command(text=UPGRADE_SENTINEL)
    )
    assert command_names.rewrite_sentence() == REWRITE_SENTENCE
    assert command_names.rewrite_sentence(by_hand=True) == BY_HAND_SENTENCE
    assert spellings.removal_message(row, "expiration") == REMOVAL + REWRITE_SENTENCE
    assert spellings.removal_message(row, "expiration", by_hand=True) == (
        REMOVAL + BY_HAND_SENTENCE
    )
