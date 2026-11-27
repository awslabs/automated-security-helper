"""The client rules judge each file of a chain as it was written.

The loader reads each file's old spellings as the canonical ones before it
merges the files, so the merged configuration holds one spelling per setting.
What it records of each file, and what the client rules and every check of a
delivered file judge, is the file as written, so a ``denied_value_patterns``
regex that names a key's text refuses the key whichever spelling the file
wrote. The rules' marking of the operator's entries applies each operator
file's own patch to a folded copy of that file, and nothing else reads that
copy.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config import client_config_policy
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_sources import resolve_config_document

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
]

#: A base whose ignore path writes the old spelling.
_ORG = {
    "global_settings": {
        "ignore_paths": [
            {"path": "build/", "reason": "generated", "expiration": "2099-01-01"}
        ]
    }
}

#: A file extending it whose suppression, and whose patch pointer, write the old
#: spelling too.
_REPO = {
    "extends": "org.yaml",
    "global_settings": {
        "suppressions": [
            {
                "rule_id": "B101",
                "path": "src/app.py",
                "reason": "reviewed",
                "expiration": "2099-01-02",
            }
        ]
    },
    "patch": [
        {
            "op": "replace",
            "path": "/global_settings/suppressions/0/expiration",
            "value": "2099-01-03",
        }
    ],
}

#: The pattern below, as a denial's reason names it.
_PATTERN_NAMED = "denied_value_patterns regex '^expiration$'"


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _chain(tmp_path: Path) -> List[Path]:
    """The base and the file that extends it, root last."""
    return [
        _write(tmp_path / "cfg" / "org.yaml", _ORG),
        _write(tmp_path / "cfg" / "repo.yaml", _REPO),
    ]


def _as_written(path: Path) -> str:
    return json.dumps(yaml.safe_load(path.read_text(encoding="utf-8")), sort_keys=False)


def _dumped(document: Any) -> str:
    return json.dumps(document, sort_keys=False)


def _judged_documents(monkeypatch) -> Dict[Path, Any]:
    """Stand in for the check of a delivered file's writes, keeping each document
    it is given under the path of the file it is judged for."""
    judged: Dict[Path, Any] = {}

    def record(document: Any, **kwargs: Any) -> List[Any]:
        judged[kwargs["document_path"]] = document
        return []

    monkeypatch.setattr(
        "automated_security_helper.config.runtime_patch.config_document_denials",
        record,
    )
    return judged


def _trusting_a_key_pattern() -> AshConfig:
    """A trusted config whose policy refuses an ignore path's key named
    ``expiration``."""
    return AshConfig.model_validate(
        {
            "global_settings": {
                "mcp": {
                    "runtime_overrides": {
                        "denied_value_patterns": {
                            "/global_settings/ignore_paths/**": "^expiration$"
                        }
                    }
                }
            }
        }
    )


def test_the_recorded_documents_are_the_files_as_written(tmp_path: Path) -> None:
    """Each file of the chain is recorded as it parses, key text and patch
    pointers included."""
    files = _chain(tmp_path)

    document = resolve_config_document(files[-1])

    assert set(document.documents) == {path.resolve() for path in files}
    for path in files:
        assert _dumped(document.documents[path.resolve()]) == _as_written(path)


def test_the_merged_document_still_reads_one_spelling(tmp_path: Path) -> None:
    """The control: the merge and the patch read the files folded, so the merged
    document holds the canonical spelling alone, the patch applied through it."""
    files = _chain(tmp_path)

    document = resolve_config_document(files[-1])

    settings = document.data["global_settings"]
    assert settings["suppressions"][0]["expires"] == "2099-01-03"
    assert settings["ignore_paths"][0]["expires"] == "2099-01-01"
    assert "expiration" not in json.dumps(document.data)


def test_the_policy_judges_each_delivered_file_as_written(
    tmp_path: Path, monkeypatch
) -> None:
    """The check of a delivered file's writes is given each file as it parses."""
    files = _chain(tmp_path)
    document = resolve_config_document(files[-1])
    judged = _judged_documents(monkeypatch)

    client_config_policy.client_file_denials(
        document.documents,
        client_config_policy.rules_from(AshConfig()),
        all_delivered=True,
    )

    assert set(judged) == {path.resolve() for path in files}
    for path in files:
        assert _dumped(judged[path.resolve()]) == _as_written(path)


def test_a_key_pattern_naming_the_old_spelling_refuses_a_delivered_file_that_writes_it(
    tmp_path: Path,
) -> None:
    """A ``denied_value_patterns`` regex is matched against the key text the
    delivered file wrote."""
    only = _write(tmp_path / "cfg" / "only.yaml", _ORG)

    found = client_config_policy.client_file_denials(
        resolve_config_document(only).documents,
        client_config_policy.rules_from(_trusting_a_key_pattern()),
        all_delivered=True,
    )

    ((path, denials),) = found
    assert path == only.resolve()
    (denial,) = denials
    assert denial.pointer.startswith("/global_settings/ignore_paths")
    assert _PATTERN_NAMED in denial.reason


def test_a_key_pattern_naming_the_old_spelling_refuses_an_operator_base_as_written(
    tmp_path: Path,
) -> None:
    """Every file of a chain a client named is judged, the operator's base
    included, as that file wrote it."""
    org = _write(tmp_path / "cfg" / "org.yaml", _ORG)
    repo = _write(tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml"})

    found = dict(
        client_config_policy.client_file_denials(
            resolve_config_document(repo).documents,
            client_config_policy.rules_from(_trusting_a_key_pattern()),
            all_delivered=True,
        )
    )

    (denial,) = found[org.resolve()]
    assert denial.pointer.startswith("/global_settings/ignore_paths")
    assert _PATTERN_NAMED in denial.reason


def test_the_marking_reads_a_folded_copy_and_leaves_each_file_as_written(
    tmp_path: Path, monkeypatch
) -> None:
    """With a delivered file in the chain, the operator's entry stays the
    operator's. The operator's file writes it in the old spelling and its own
    patch rewrites its expiry through the canonical one, so only a copy of that
    file with its old spellings read as the canonical ones, that patch applied to
    it, holds the entry the configuration holds. The checks of the delivered file
    and the recorded documents still hold each file as written."""
    org = _write(
        tmp_path / "cfg" / "org.yaml",
        {
            "global_settings": {
                "suppressions": [
                    {
                        "rule_id": "B101",
                        "path": "src/app.py",
                        "reason": "reviewed",
                        "expiration": "2099-01-02",
                    }
                ]
            },
            "patch": [
                {
                    "op": "replace",
                    "path": "/global_settings/suppressions/0/expires",
                    "value": "2099-06-30",
                }
            ],
        },
    )
    repo = _write(tmp_path / "cfg" / "repo.yaml", {"extends": "org.yaml", **_ORG})
    document = resolve_config_document(repo)
    config = AshConfig.model_validate(document.data)
    monkeypatch.setattr(
        "automated_security_helper.config.mcp_sandbox.config_is_client_supplied",
        lambda path: Path(path).name == "repo.yaml",
    )
    judged = _judged_documents(monkeypatch)

    marked = client_config_policy.apply_client_config_rules(
        config,
        document.documents,
        rules=client_config_policy.rules_from(AshConfig()),
        trusted_config_path=None,
        source_dir=tmp_path,
        permit_base=None,
    )

    # The marking ran: the operator's entry, as its own patch left it, is the
    # operator's, and the delivered file's is the client's.
    (suppression,) = marked.global_settings.suppressions
    (ignored,) = marked.global_settings.ignore_paths
    assert suppression.expires == "2099-06-30"
    assert suppression.client_supplied is False
    assert ignored.client_supplied is True
    assert set(judged) == {repo.resolve()}
    assert _dumped(judged[repo.resolve()]) == _as_written(repo)
    recorded = {path: document.documents[path.resolve()] for path in (org, repo)}
    for path, written in recorded.items():
        assert _dumped(written) == _as_written(path)
    assert "expiration" in recorded[org]["global_settings"]["suppressions"][0]
    assert "expiration" in recorded[repo]["global_settings"]["ignore_paths"][0]
