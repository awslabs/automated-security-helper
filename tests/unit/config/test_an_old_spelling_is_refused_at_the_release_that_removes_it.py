"""An old spelling of a renamed key loads until the release that removes it.

``expiration``, the earlier spelling of ``expires``, loads with a deprecation
line through 3.x and is refused from 4.0 on, naming the canonical spelling. The
running version decides, so the 4.0 release refuses it with no edit to the
models. A results file a scan already wrote is a record and keeps loading at
every version.

A ``patch`` op is part of its file: a pointer or an op's value that names the
old spelling is refused at 4.0 as a key is, naming the file.

Red at the base: at 4.0 a config, a base it extends, an op's value and an entry
validated outside the loader all still loaded the old spelling, and a pointer in
it failed to apply without naming either spelling.
"""

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml
from pydantic import ValidationError

import automated_security_helper
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

REMOVAL_RELEASE = "4.0.0"

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


def test_an_entry_validated_outside_the_loader_is_refused_at_the_removal_release(
    running,
) -> None:
    running(REMOVAL_RELEASE)

    with pytest.raises(ValidationError) as refused:
        AshSuppression.model_validate({**_ENTRY, "expiration": "2099-01-01"})

    assert "expires" in str(refused.value)


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
