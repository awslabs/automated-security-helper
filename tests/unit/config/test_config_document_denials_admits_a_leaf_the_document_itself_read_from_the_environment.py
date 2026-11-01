# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A leaf the document's own file read from the environment is admitted.

``config_document_denials`` refuses a leaf at an environment-read pointer of
the trusted config whatever the document writes there, so a client cannot use
the absence of a refusal as an oracle for the value. A session's client-patched
copy of the operator's profile (``repeats_trusted``) repeats the operator's own
environment reads: the copy's file wrote the same reference, so the client can
read that reference in its own copy already, and the leaf answers nothing.
With ``own_references`` naming the references the document's own file read
(``EnvironmentReference`` with ``origin`` set to the document's path), such a
leaf is admitted when every environment-read pointer it covers was written by
the document itself as the same reference text the trusted config's record
holds there.

Red at the base (tip47): ``config_document_denials`` takes no
``own_references`` keyword, so the admitting call raises ``TypeError``.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Sequence

import pytest

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.environment_record import EnvironmentReference
from automated_security_helper.config.runtime_patch import config_document_denials

pytestmark = pytest.mark.unit

CANARY = "ash-canary-t48a-0123456789"

ALLOWLIST = RuntimeOverridesConfig(
    enabled=True,
    allowed_paths=["/global_settings/**"],
    denied_paths=["/project_name"],
)


@pytest.fixture
def trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A trusted config whose project_name the file wrote as a reference."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_T48", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text("project_name: ${ASH_T48}\n", encoding="utf-8")
    _, config = load_config_file_for_run(path)
    assert config.project_name == CANARY, "the control: the reference was read"
    return config


def _own_reference(trusted, document_path: Path) -> EnvironmentReference:
    """The trusted record's project_name reference, as the document's own."""
    reference = next(
        each
        for each in (getattr(trusted, "_environment_references", None) or ())
        if tuple(each.path) == ("project_name",) and not each.key
    )
    assert reference.written == "${ASH_T48}", "the control: the record's text"
    return replace(reference, origin=(document_path, tuple(reference.path)))


def _denied(
    trusted,
    *,
    repeats_trusted: bool = True,
    own_references: Sequence[EnvironmentReference] = (),
) -> List[str]:
    document: Dict[str, Any] = {"project_name": CANARY}
    return [
        denial.key
        for denial in config_document_denials(
            document,
            allowlist=ALLOWLIST,
            config=trusted,
            repeats_trusted=repeats_trusted,
            own_references=own_references,
        )
    ]


def test_a_leaf_the_document_itself_read_is_admitted(trusted, tmp_path: Path) -> None:
    """Id 1: red at tip47 (TypeError: unexpected keyword argument
    'own_references'); green with the keyword and the admission arm."""
    own = _own_reference(trusted, tmp_path / "copy.yaml")
    assert _denied(trusted, repeats_trusted=True, own_references=(own,)) == []


def test_without_own_references_the_denial_stands(trusted) -> None:
    """Id 2 (control): the tip47 behavior, green both sides."""
    assert _denied(trusted, repeats_trusted=True, own_references=()) == [
        "project_name"
    ]


def test_a_reference_written_differently_is_refused(trusted, tmp_path: Path) -> None:
    """Id 3 (control): the document's own reference text differs from the
    trusted record's, so the leaf still answers."""
    own = _own_reference(trusted, tmp_path / "copy.yaml")
    other = replace(own, written="${ASH_T48_OTHER}")
    assert _denied(trusted, repeats_trusted=True, own_references=(other,)) == [
        "project_name"
    ]


def test_without_repeats_trusted_the_denial_stands(trusted, tmp_path: Path) -> None:
    """Id 4 (control): own references admit nothing outside a client-patched
    copy of the trusted profile."""
    own = _own_reference(trusted, tmp_path / "copy.yaml")
    assert _denied(trusted, repeats_trusted=False, own_references=(own,)) == [
        "project_name"
    ]
