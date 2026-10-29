# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A document that repeats a value the trusted config read from the environment
is not exempt from a denial of that field.

``config_document_denials`` exempts a leaf whose value equals what the trusted
config has at the same place, so a document that writes the defaults is not
refused. For a leaf the trusted config read from the environment the exemption
was an oracle: a client could write a guess at the value into a denied field and
learn from the absence of a refusal that the guess was right. Such a leaf is now
refused whatever the document writes there; a literal leaf the trusted config
holds is still exempt.

Red at the base: the document repeating the environment value drew no denial.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.runtime_patch import config_document_denials

pytestmark = pytest.mark.unit

CANARY = "ash-canary-x25a-0123456789"
LITERAL_IGNORE = {"path": "vendored/**", "reason": "vendored"}

ALLOWLIST = RuntimeOverridesConfig(
    enabled=True,
    allowed_paths=["/global_settings/**"],
    denied_paths=["/project_name", "/global_settings/ignore_paths"],
)


@pytest.fixture
def trusted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A trusted config whose project_name the file wrote as a reference."""
    from automated_security_helper.config.resolve_config import load_config_file_for_run

    monkeypatch.setenv("ASH_X25_PN", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash.yaml"
    path.write_text(
        "project_name: ${ASH_X25_PN}\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: vendored/**\n"
        "      reason: vendored\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)
    assert config.project_name == CANARY, "the control: the reference was read"
    return config


def _denied(document: Dict[str, Any], trusted) -> List[str]:
    return [
        denial.key
        for denial in config_document_denials(
            document, allowlist=ALLOWLIST, config=trusted
        )
    ]


def test_a_document_repeating_the_environment_value_is_refused(trusted) -> None:
    assert _denied({"project_name": CANARY}, trusted) == ["project_name"]


def test_a_document_with_another_value_is_refused_as_before(trusted) -> None:
    """The control: a right and a wrong guess read the same."""
    assert _denied({"project_name": "ash-canary-0000-9876543210"}, trusted) == [
        "project_name"
    ]


def test_a_document_repeating_a_literal_value_is_still_exempt(trusted) -> None:
    """The control: the exemption stands for a value the file wrote as text."""
    document = {"global_settings": {"ignore_paths": [dict(LITERAL_IGNORE)]}}

    assert _denied(document, trusted) == []
