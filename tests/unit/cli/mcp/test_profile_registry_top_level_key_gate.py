# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The strict top-level key gate of ``register_profiles`` judges the loaded text.

Three readings of one loop. The gate used to resolve the profile's ``extends``
chain a second time and read each file from disk again, so an edit between the
load and the check was judged in place of the file the load read. It took its
allowed keys from the model alone, which does not declare ``$schema``, a key the
config validator accepts in a JSON config. And it sorted the unknown keys, which
raises when a YAML key such as ``on:`` parses as a boolean beside a string key,
so the refusal said the schema re-validation failed instead of naming the key.

The loader is replaced by a stand-in that hands back the text it "read", so
these tests drive the gate alone: what the profile's file holds on disk, what
the load parsed, and what the gate reports are three separate inputs here.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import pytest

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.profile_registry import (
    ProfileRegistryError,
    register_profiles,
)
from automated_security_helper.config import resolve_config
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


def _loader_of(text_by_path: Dict[Path, str]):
    """A stand-in for ``load_config_file_for_run`` that read ``text_by_path``.

    Fills the caller's ``texts`` cache as the real loader's reader does, keyed by
    resolved path, and returns a document whose chain is those files.
    """

    def load(
        config_path: Any,
        reads: Optional[Dict[Path, Any]] = None,
        texts: Optional[Dict[Path, str]] = None,
        **kwargs: Any,
    ):
        chain = []
        for path, text in text_by_path.items():
            key = Path(path).resolve()
            if texts is not None:
                texts[key] = text
            chain.append(key)
        return SimpleNamespace(chain=chain), AshConfig()

    return load


def test_the_gate_judges_the_text_the_load_read_not_the_disk(
    tmp_path: Path, monkeypatch
) -> None:
    """The file on disk holds a typo; the text the load read does not. The
    gate judges what was loaded, and reads no file a second time."""
    profile = tmp_path / "p.yaml"
    profile.write_text("not_a_field: 1\n", encoding="utf-8")
    monkeypatch.setattr(
        resolve_config,
        "load_config_file_for_run",
        _loader_of({profile: "project_name: loaded\n"}),
    )

    def disk_read(path: Path):
        raise AssertionError(f"read {path} from disk a second time")

    monkeypatch.setattr(profile_registry, "read_config_file_literally", disk_read)

    registry = register_profiles([f"p={profile}"])

    assert set(registry) == {"p"}


def test_a_json_profile_with_a_schema_reference_registers(
    tmp_path: Path, monkeypatch
) -> None:
    """``$schema`` is a key the config validator accepts and a scan ignores."""
    profile = tmp_path / "p.json"
    text = '{"$schema": "https://example.invalid/ash.json", "project_name": "p"}\n'
    profile.write_text(text, encoding="utf-8")
    monkeypatch.setattr(
        resolve_config, "load_config_file_for_run", _loader_of({profile: text})
    )

    registry = register_profiles([f"p={profile}"])

    assert set(registry) == {"p"}


def test_a_boolean_key_is_named_in_the_refusal(tmp_path: Path, monkeypatch) -> None:
    """YAML reads ``on:`` as ``True``; the refusal names it beside the string key
    instead of failing to order the two."""
    profile = tmp_path / "p.yaml"
    text = "on: {}\nzzz_typo: 1\nproject_name: p\n"
    profile.write_text(text, encoding="utf-8")
    monkeypatch.setattr(
        resolve_config, "load_config_file_for_run", _loader_of({profile: text})
    )

    with pytest.raises(ProfileRegistryError) as refused:
        register_profiles([f"p={profile}"])

    message = str(refused.value)
    assert "unknown top-level field" in message, message
    assert "True (a bool key, not a field name)" in message, message
    assert "zzz_typo" in message, message
    assert "re-validation against schema failed" not in message, message
