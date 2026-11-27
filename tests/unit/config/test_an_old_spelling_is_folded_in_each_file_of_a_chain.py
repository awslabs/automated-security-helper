"""Each file of an ``extends`` chain has its old spellings read as the canonical ones.

The loader folds a file's old spellings (``expiration`` for ``expires``) onto
the canonical key before it layers the file over another. So:

* the deprecation is said once per file and spelling, naming the file, rather
  than once per entry with no file;
* a file that writes both spellings with different values is refused naming
  that file, whichever file of the chain it is;
* a ``patch`` pointer in either spelling reaches the key the merged document
  holds, so a child and its base can each be written in either spelling;
* a key that is canonical in another model (a content database staleness
  override's ``expiration``) is left as written.

Red at the base: three entries gave three unnamed lines; a disagreement in a
base was refused naming the extending file; a pointer in the other spelling
than the base's failed to apply.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

DEPRECATION = "deprecated spelling of 'expires'"


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _suppression(**expiry: str) -> Dict[str, Any]:
    return {"rule_id": "B101", "path": "src/app.py", "reason": "reviewed", **expiry}


def _deprecation_lines(config: AshConfig) -> List[str]:
    return [line for line in config._resolution_warnings if DEPRECATION in line]


def test_the_deprecation_is_said_once_per_file_naming_the_file(tmp_path: Path) -> None:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {
            "global_settings": {
                "ignore_paths": [
                    {
                        "path": "build/",
                        "reason": "generated",
                        "expiration": "2099-01-01",
                    },
                    {
                        "path": "dist/",
                        "reason": "generated",
                        "expiration": "2099-01-02",
                    },
                ]
            }
        },
    )
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {
            "extends": "org.yaml",
            "global_settings": {
                "suppressions": [_suppression(expiration="2099-01-03")],
            },
        },
    )

    config = AshConfig.from_file(child)

    lines = _deprecation_lines(config)
    assert len(lines) == 2, lines
    assert sum("org.yaml" in line for line in lines) == 1, lines
    assert sum("repo.yaml" in line for line in lines) == 1, lines
    # Every entry still reads its expiry.
    assert [p.expires for p in config.global_settings.ignore_paths] == [
        "2099-01-01",
        "2099-01-02",
    ]
    assert config.global_settings.suppressions[0].expires == "2099-01-03"


def test_the_operators_overlay_file_is_folded_too(tmp_path: Path) -> None:
    """The operator's file layered over a project's is a file of its own."""
    from automated_security_helper.config.resolve_config import resolve_config

    project = _write(tmp_path / "repo" / ".ash.yaml", {"fail_on_findings": True})
    operator = _write(
        tmp_path / "operator" / "ops.yaml",
        {"global_settings": {"suppressions": [_suppression(expiration="2099-01-03")]}},
    )

    config = resolve_config(
        config_path=project,
        source_dir=tmp_path / "repo",
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    lines = _deprecation_lines(config)
    assert len(lines) == 1, lines
    assert "ops.yaml" in lines[0], lines
    assert config.global_settings.suppressions[0].expires == "2099-01-03"


def test_a_disagreement_in_a_base_is_refused_naming_the_base(tmp_path: Path) -> None:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {
            "global_settings": {
                "suppressions": [
                    _suppression(expires="2099-01-01", expiration="2098-01-01")
                ]
            }
        },
    )
    child = _write(
        tmp_path / "cfg" / "repo.yaml",
        {"extends": "org.yaml", "fail_on_findings": False},
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(child)

    message = str(refused.value)
    assert "org.yaml" in message
    assert "expires" in message
    assert "expiration" in message


def test_a_disagreement_in_a_file_with_no_extends_is_refused_naming_it(
    tmp_path: Path,
) -> None:
    """The control: a lone file was refused, and still is, naming it."""
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        {
            "global_settings": {
                "suppressions": [
                    _suppression(expires="2099-01-01", expiration="2098-01-01")
                ]
            }
        },
    )

    with pytest.raises(ASHConfigValidationError) as refused:
        AshConfig.from_file(config)

    message = str(refused.value)
    assert "only.yaml" in message
    assert "expires" in message
    assert "expiration" in message


def _child_patching(tmp_path: Path, base_entry: Dict[str, Any], ops: List[Any]) -> Path:
    _write(
        tmp_path / "cfg" / "org.yaml",
        {"global_settings": {"suppressions": [base_entry]}},
    )
    return _write(tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml", "patch": ops})


@pytest.mark.parametrize(
    "base_spelling,pointer_spelling",
    [("expires", "expiration"), ("expiration", "expires")],
    ids=["old-pointer-over-canonical-base", "canonical-pointer-over-old-base"],
)
def test_a_childs_patch_reaches_the_bases_expiry_in_either_spelling(
    tmp_path: Path, base_spelling: str, pointer_spelling: str
) -> None:
    child = _child_patching(
        tmp_path,
        _suppression(**{base_spelling: "2099-01-01"}),
        [
            {
                "op": "replace",
                "path": f"/global_settings/suppressions/0/{pointer_spelling}",
                "value": "2199-12-31",
            }
        ],
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.suppressions[0].expires == "2199-12-31"


def test_a_childs_test_op_reads_the_bases_expiry_in_the_old_spelling(
    tmp_path: Path,
) -> None:
    child = _child_patching(
        tmp_path,
        _suppression(expires="2099-01-01"),
        [
            {
                "op": "test",
                "path": "/global_settings/suppressions/0/expiration",
                "value": "2099-01-01",
            },
            {
                "op": "replace",
                "path": "/global_settings/suppressions/0/reason",
                "value": "re-reviewed",
            },
        ],
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.suppressions[0].reason == "re-reviewed"


def test_a_childs_patch_in_the_bases_own_old_spelling_still_applies(
    tmp_path: Path,
) -> None:
    """The control: both files in the old spelling, as before the fold existed."""
    child = _child_patching(
        tmp_path,
        _suppression(expiration="2099-01-01"),
        [
            {
                "op": "replace",
                "path": "/global_settings/suppressions/0/expiration",
                "value": "2199-12-31",
            }
        ],
    )

    config = AshConfig.from_file(child)

    assert config.global_settings.suppressions[0].expires == "2199-12-31"


def test_a_staleness_overrides_expiration_is_its_own_canonical_key(
    tmp_path: Path,
) -> None:
    """``expiration`` is the required, canonical key of this model: left alone."""
    config = _write(
        tmp_path / "cfg" / "only.yaml",
        {
            "content_db_staleness_overrides": [
                {
                    "database": "grype-db",
                    "policy": "warn",
                    "expiration": "2099-01-01",
                    "reason": "upstream paused",
                }
            ]
        },
    )

    loaded = AshConfig.from_file(config)

    assert loaded.content_db_staleness_overrides[0].expiration == "2099-01-01"
    assert _deprecation_lines(loaded) == []
