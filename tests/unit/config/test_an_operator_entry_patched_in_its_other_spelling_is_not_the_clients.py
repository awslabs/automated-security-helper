"""An operator's entry stays the operator's whichever spelling its own patch uses.

The client rules mark each suppression and ignore path no operator file
supplied as ``client_supplied``. An entry is the operator's when it equals one
in an operator file with that file's own ``patch`` applied. Each file is
recorded as written, so its patch is applied to a copy with its old spellings
read as the canonical ones, as the loader applied it: a pointer that names the
entry's expiry in the other spelling than the entry reaches it there too.
"""

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.config import client_config_policy
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import resolve_config_document
from automated_security_helper.models.core import AshSuppression

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

_ENTRY = {"rule_id": "B101", "path": "src/app.py", "reason": "reviewed"}


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "written,pointer",
    [("expiration", "expires"), ("expires", "expiration")],
    ids=["old-entry-canonical-pointer", "canonical-entry-old-pointer"],
)
def test_an_operator_entry_its_patch_names_in_the_other_spelling_is_not_the_clients(
    tmp_path: Path, monkeypatch, written: str, pointer: str
) -> None:
    """With client overrides in play, the operator's entry patched through a
    pointer in its other spelling is not marked, and an entry no file wrote is."""
    operator = _write(
        tmp_path / "cfg" / "op.yaml",
        {
            "global_settings": {"suppressions": [{**_ENTRY, written: "2099-01-01"}]},
            "patch": [
                {
                    "op": "replace",
                    "path": f"/global_settings/suppressions/0/{pointer}",
                    "value": "2099-06-30",
                }
            ],
        },
    )
    document = resolve_config_document(operator)
    config = AshConfig.model_validate(document.data)
    config.global_settings.suppressions.append(
        AshSuppression.model_validate({**_ENTRY, "path": "src/client.py"})
    )
    monkeypatch.setattr(
        "automated_security_helper.config.mcp_sandbox.config_is_client_supplied",
        lambda _path: False,
    )

    marked = client_config_policy.apply_client_config_rules(
        config,
        document.documents,
        rules=client_config_policy.rules_from(AshConfig()),
        trusted_config_path=None,
        source_dir=tmp_path,
        permit_base=None,
        client_overrides=True,
    )

    assert [
        (entry.path, entry.expires, entry.client_supplied)
        for entry in marked.global_settings.suppressions
    ] == [("src/app.py", "2099-06-30", False), ("src/client.py", None, True)]
