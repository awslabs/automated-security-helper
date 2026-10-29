# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A setting spelled two ways is merged as the one setting the config model reads.

``config_sources.deep_merge`` merges a child over its ``extends`` bases and, in
workspace mode, the operator's ``--config`` over a project's own config. Both
must give the setting the config model actually reads, whichever spellings the
two documents use: the field name (``cdk_nag``), its alias (``cdk-nag``), both,
or a spelling the model does not read at all (``global-settings``).
"""

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _write(path: Path, document: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _layered(tmp_path: Path, project: Dict[str, Any], operator: Dict[str, Any]):
    project_file = _write(tmp_path / "repo" / ".ash" / ".ash.yaml", project)
    operator_file = _write(tmp_path / "operator" / "ash.yaml", operator)
    return resolve_config(
        config_path=project_file,
        source_dir=tmp_path / "repo",
        trusted_config_path=operator_file,
        overlay_config_path=operator_file,
    )


def _extended(tmp_path: Path, base: Dict[str, Any], child: Dict[str, Any]):
    _write(tmp_path / "cfg" / "base.yaml", base)
    child_file = _write(
        tmp_path / "cfg" / "child.yaml", {"extends": "base.yaml", **child}
    )
    return AshConfig.from_file(child_file)


def _cdk_nag(config: AshConfig) -> Any:
    return config.scanners.cdk_nag.enabled


def _gitlab_sast(config: AshConfig) -> Any:
    return config.reporters.gitlab_sast.enabled


def _max_scans(config: AshConfig) -> Any:
    return config.mcp_resource_management.max_concurrent_scans


#: (case, lower document, upper document, reader, value the upper document gives)
CASES = [
    (
        "field name over alias",
        {"scanners": {"cdk-nag": {"enabled": True}}},
        {"scanners": {"cdk_nag": {"enabled": False}}},
        _cdk_nag,
        False,
    ),
    (
        "alias over field name",
        {"scanners": {"cdk_nag": {"enabled": True}}},
        {"scanners": {"cdk-nag": {"enabled": False}}},
        _cdk_nag,
        False,
    ),
    (
        "field name over both spellings",
        {"scanners": {"cdk-nag": {"enabled": True}, "cdk_nag": {}}},
        {"scanners": {"cdk_nag": {"enabled": False}}},
        _cdk_nag,
        False,
    ),
    (
        "alias over both spellings",
        {"scanners": {"cdk-nag": {"enabled": True}, "cdk_nag": {"enabled": True}}},
        {"scanners": {"cdk-nag": {"enabled": False}}},
        _cdk_nag,
        False,
    ),
    (
        "reporter field name over both spellings",
        {"reporters": {"gitlab-sast": {"enabled": True}, "gitlab_sast": {}}},
        {"reporters": {"gitlab_sast": {"enabled": False}}},
        _gitlab_sast,
        False,
    ),
    (
        "top-level field name over both spellings",
        {
            "mcp-resource-management": {"max_concurrent_scans": 9},
            "mcp_resource_management": {},
        },
        {"mcp_resource_management": {"max_concurrent_scans": 2}},
        _max_scans,
        2,
    ),
    (
        "unread spelling of a section beside the read one",
        {"global-settings": {}},
        {"global_settings": {"severity_threshold": "LOW"}},
        lambda c: c.global_settings.severity_threshold,
        "LOW",
    ),
    (
        "unread spelling of a list field",
        {"ash-plugin-modules": []},
        {"ash_plugin_modules": ["json"]},
        lambda c: c.ash_plugin_modules,
        ["json"],
    ),
    (
        "unread spelling of an option",
        {"scanners": {"cdk-nag": {"options": {"nag-packs": {}}}}},
        {
            "scanners": {
                "cdk-nag": {"options": {"nag_packs": {"HIPAASecurityChecks": True}}}
            }
        },
        lambda c: c.scanners.cdk_nag.options.nag_packs.HIPAASecurityChecks,
        True,
    ),
]


@pytest.mark.parametrize(
    "lower,upper,read,expected",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_the_operators_setting_is_final_whatever_the_projects_spelling(
    tmp_path, lower, upper, read, expected
):
    assert read(_layered(tmp_path, lower, upper)) == expected


@pytest.mark.parametrize(
    "lower,upper,read,expected",
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_a_child_wins_over_its_base_whatever_the_bases_spelling(
    tmp_path, lower, upper, read, expected
):
    assert read(_extended(tmp_path, lower, upper)) == expected


def test_the_upper_documents_other_spelling_reaches_the_lower_setting(tmp_path):
    """As before: a key that differs only in '-' versus '_' reaches the lower
    document's spelling of the setting, and the upper value wins there."""
    config = _layered(
        tmp_path,
        {"global_settings": {"severity_threshold": "HIGH"}},
        {"global-settings": {"severity_threshold": "LOW"}},
    )

    assert config.global_settings.severity_threshold == "LOW"


def test_the_upper_documents_read_spelling_wins_over_its_unread_one(tmp_path):
    config = _layered(
        tmp_path,
        {"global_settings": {"severity_threshold": "HIGH"}},
        {
            "global_settings": {"severity_threshold": "CRITICAL"},
            "global-settings": {"severity_threshold": "LOW"},
        },
    )

    assert config.global_settings.severity_threshold == "CRITICAL"


def test_a_section_the_upper_document_leaves_alone_keeps_both_spellings(tmp_path):
    config = _layered(
        tmp_path,
        {"scanners": {"cdk-nag": {"enabled": False}, "cdk_nag": {"enabled": True}}},
        {"fail_on_findings": True},
    )

    # The project alone reads the alias over the field name.
    assert config.scanners.cdk_nag.enabled is False


def test_a_childs_patch_reaches_the_merged_section(tmp_path):
    """The merge leaves one spelling, so a patch pointer in either spelling finds it."""
    _write(tmp_path / "cfg" / "base.yaml", {"scanners": {"cdk-nag": {"enabled": True}}})
    child = _write(
        tmp_path / "cfg" / "child.yaml",
        {
            "extends": "base.yaml",
            "scanners": {"cdk_nag": {"options": {}}},
            "patch": [
                {"op": "replace", "path": "/scanners/cdk_nag/enabled", "value": False}
            ],
        },
    )

    assert AshConfig.from_file(child).scanners.cdk_nag.enabled is False


def _plugin_section(config: AshConfig, kind: str, name: str) -> Dict[str, Any]:
    found = config.get_plugin_config(kind, name)
    return found if isinstance(found, dict) else found.model_dump()


#: (lower key, upper key): two spellings of one plugin section that
#: get_plugin_config reads for the plugin named by the first.
_SECTION_SPELLINGS = [
    ("my-reporter", "MyReporter"),
    ("MyReporter", "my-reporter"),
    ("my-reporter", "my_reporter"),
]


@pytest.mark.parametrize("lower_key,upper_key", _SECTION_SPELLINGS)
def test_a_plugin_section_the_operator_spells_another_way_is_final(
    tmp_path, lower_key, upper_key
):
    config = _layered(
        tmp_path,
        {"reporters": {lower_key: {"enabled": True, "options": {"depth": 7}}}},
        {"reporters": {upper_key: {"enabled": False}}},
    )

    section = _plugin_section(config, "reporter", "my-reporter")
    assert section["enabled"] is False
    # The project's other settings in its spelling of the section still apply.
    assert section["options"] == {"depth": 7}


@pytest.mark.parametrize("lower_key,upper_key", _SECTION_SPELLINGS)
def test_a_child_spelling_a_plugin_section_another_way_wins(
    tmp_path, lower_key, upper_key
):
    config = _extended(
        tmp_path,
        {"reporters": {lower_key: {"enabled": True}}},
        {"reporters": {upper_key: {"enabled": False}}},
    )

    assert _plugin_section(config, "reporter", "my-reporter")["enabled"] is False


def test_the_operators_bedrock_section_spelled_another_way_is_final(tmp_path):
    """BedrockSummary is a spelling get_plugin_config reads for the Bedrock reporter."""
    config = _layered(
        tmp_path,
        {"reporters": {"bedrock-summary-reporter": {"enabled": True}}},
        {"reporters": {"BedrockSummary": {"enabled": False}}},
    )

    assert (
        _plugin_section(config, "reporter", "bedrock-summary-reporter")["enabled"]
        is False
    )


def test_a_scanner_section_the_operator_spells_another_way_is_final(tmp_path):
    config = _layered(
        tmp_path,
        {"scanners": {"trivy-repo": {"enabled": True}}},
        {"scanners": {"TrivyRepo": {"enabled": False}}},
    )

    assert _plugin_section(config, "scanner", "trivy-repo")["enabled"] is False
