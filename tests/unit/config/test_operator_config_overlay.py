# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``resolve_config(overlay_config_path=...)``: a config file layered over the selected one.

Workspace mode passes the operator's ``--config`` here for a project that has a
config of its own, so every field the operator sets is final and the project's
file fills only the fields the operator left unset. The merge is the ``extends``
rule (``config_sources.deep_merge``) with the overlay as the child: mappings
merge key by key, and a list or scalar the overlay sets replaces the project's.
"""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _write(path: Path, document) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _project(tmp_path: Path, document) -> Path:
    return _write(tmp_path / "repo" / ".ash" / ".ash.yaml", document)


def _operator(tmp_path: Path, document) -> Path:
    return _write(tmp_path / "operator" / "ash.yaml", document)


def _resolve(tmp_path: Path, project: Path, operator: Path, **kwargs):
    return resolve_config(
        config_path=project,
        source_dir=tmp_path / "repo",
        trusted_config_path=operator,
        overlay_config_path=operator,
        **kwargs,
    )


def test_a_field_the_operator_sets_is_final(tmp_path):
    project = _project(
        tmp_path,
        {"fail_on_findings": False, "fail_on_incomplete_scanners": False},
    )
    operator = _operator(
        tmp_path, {"fail_on_findings": True, "fail_on_incomplete_scanners": True}
    )

    config = _resolve(tmp_path, project, operator)

    assert config.fail_on_findings is True
    assert config.fail_on_incomplete_scanners is True


def test_a_field_set_to_its_default_in_the_operators_file_is_still_final(tmp_path):
    """Set means present in the file, not different from the default."""
    project = _project(tmp_path, {"global_settings": {"severity_threshold": "LOW"}})
    operator = _operator(
        tmp_path, {"global_settings": {"severity_threshold": "MEDIUM"}}
    )

    config = _resolve(tmp_path, project, operator)

    assert config.global_settings.severity_threshold == "MEDIUM"


def test_a_field_only_the_project_sets_is_kept(tmp_path):
    project = _project(
        tmp_path,
        {"scanners": {"bandit": {"options": {"confidence_level": "high"}}}},
    )
    operator = _operator(tmp_path, {"fail_on_findings": True})

    config = _resolve(tmp_path, project, operator)

    assert config.scanners.bandit.options.confidence_level == "high"
    assert config.fail_on_findings is True


def test_mappings_merge_key_by_key(tmp_path):
    project = _project(
        tmp_path,
        {"scanners": {"bandit": {"options": {"confidence_level": "high"}}}},
    )
    operator = _operator(tmp_path, {"scanners": {"bandit": {"enabled": False}}})

    config = _resolve(tmp_path, project, operator)

    assert config.scanners.bandit.enabled is False
    assert config.scanners.bandit.options.confidence_level == "high"


def test_a_list_the_operator_sets_replaces_the_projects(tmp_path):
    project = _project(
        tmp_path,
        {
            "global_settings": {
                "suppressions": [
                    {"rule_id": "B101", "path": "tests/**", "reason": "project"}
                ]
            }
        },
    )
    operator = _operator(
        tmp_path,
        {
            "global_settings": {
                "suppressions": [
                    {"rule_id": "B602", "path": "tools/**", "reason": "operator"}
                ]
            }
        },
    )

    config = _resolve(tmp_path, project, operator)

    assert [s.rule_id for s in config.global_settings.suppressions] == ["B602"]


def test_the_operators_patch_applies_to_its_own_file_before_the_layering(tmp_path):
    """The operator's file means one thing, layered or alone: its patch adds to
    its own list, and that list then replaces the project's."""
    project = _project(
        tmp_path,
        {
            "global_settings": {
                "suppressions": [
                    {"rule_id": "B101", "path": "tests/**", "reason": "project"}
                ]
            }
        },
    )
    operator = _operator(
        tmp_path,
        {
            "global_settings": {
                "suppressions": [
                    {"rule_id": "B602", "path": "tools/**", "reason": "operator"}
                ]
            },
            "patch": [
                {
                    "op": "add",
                    "path": "/global_settings/suppressions/-",
                    "value": {
                        "rule_id": "B603",
                        "path": "tools/**",
                        "reason": "operator",
                    },
                }
            ],
        },
    )

    config = _resolve(tmp_path, project, operator)

    assert [s.rule_id for s in config.global_settings.suppressions] == [
        "B602",
        "B603",
    ]


def test_the_operators_patch_applies_to_its_own_file_when_used_alone(tmp_path):
    missing = tmp_path / "repo" / ".ash" / ".ash.yaml"
    (tmp_path / "repo").mkdir()
    operator = _operator(
        tmp_path,
        {
            "project_name": "before",
            "patch": [{"op": "replace", "path": "/project_name", "value": "after"}],
        },
    )

    config = _resolve(tmp_path, missing, operator)

    assert config.project_name == "after"


def test_config_overrides_still_win_over_the_operators_file(tmp_path):
    project = _project(tmp_path, {"fail_on_findings": False})
    operator = _operator(tmp_path, {"fail_on_findings": True})

    config = _resolve(
        tmp_path, project, operator, config_overrides=["fail_on_findings=false"]
    )

    assert config.fail_on_findings is False


def test_a_grant_the_operator_sets_is_kept_over_the_projects(tmp_path):
    """The operator's file is the trusted base, so the confinement keeps its value."""
    project = _project(tmp_path, {"sandbox": {"extra_read_paths": ["/project/x"]}})
    operator = _operator(tmp_path, {"sandbox": {"extra_read_paths": ["/operator/x"]}})

    config = _resolve(tmp_path, project, operator)

    assert config.sandbox.extra_read_paths == ["/operator/x"]


def test_a_grant_only_the_project_sets_is_still_confined(tmp_path):
    project = _project(tmp_path, {"sandbox": {"extra_read_paths": ["/project/x"]}})
    operator = _operator(tmp_path, {"fail_on_findings": True})

    config = _resolve(tmp_path, project, operator)

    assert config.sandbox.extra_read_paths == []


def test_an_overlay_inside_the_scanned_tree_grants_nothing(tmp_path):
    """Layering does not make a file the operator's: where it sits decides."""
    project = _project(tmp_path, {})
    inside = _write(
        tmp_path / "repo" / "ops.yaml",
        {"sandbox": {"extra_read_paths": ["/inside/x"]}},
    )

    config = resolve_config(
        config_path=project,
        source_dir=tmp_path / "repo",
        trusted_config_path=inside,
        overlay_config_path=inside,
    )

    assert config.sandbox.extra_read_paths == []


def test_the_overlays_extends_chain_counts_as_set(tmp_path):
    base = _write(tmp_path / "operator" / "base.yaml", {"fail_on_findings": True})
    operator = _write(
        tmp_path / "operator" / "ash.yaml", {"extends": base.name, "project_name": "x"}
    )
    project = _project(tmp_path, {"fail_on_findings": False})

    config = _resolve(tmp_path, project, operator)

    assert config.fail_on_findings is True
    assert config.project_name == "x"


def test_a_project_config_that_cannot_be_read_falls_back_to_the_overlay(tmp_path):
    """Not to the built-in defaults, which would drop the operator's settings."""
    project = tmp_path / "repo" / ".ash" / ".ash.yaml"
    project.parent.mkdir(parents=True)
    project.write_text("fail_on_findings: [unclosed\n", encoding="utf-8")
    operator = _operator(tmp_path, {"fail_on_incomplete_scanners": True})

    config = _resolve(tmp_path, project, operator)

    assert config.fail_on_incomplete_scanners is True
    assert any(
        "Failed to load configuration file" in warning
        for warning in config._resolution_warnings
    )


def test_a_missing_overlay_is_refused(tmp_path):
    project = _project(tmp_path, {})
    missing = tmp_path / "operator" / "gone.yaml"

    with pytest.raises(ASHConfigSourceError, match="gone.yaml"):
        resolve_config(
            config_path=project,
            source_dir=tmp_path / "repo",
            overlay_config_path=missing,
        )


def test_an_overlay_that_does_not_validate_is_refused_and_named(tmp_path):
    project = _project(tmp_path, {})
    operator = _operator(tmp_path, {"fail_on_findings": "sometimes"})

    with pytest.raises(ASHConfigValidationError, match="operator"):
        _resolve(tmp_path, project, operator)


def test_an_overlay_cannot_be_combined_with_an_untrusted_config(tmp_path):
    project = _project(tmp_path, {})
    operator = _operator(tmp_path, {})

    with pytest.raises(ValueError, match="untrusted_config"):
        _resolve(tmp_path, project, operator, untrusted_config=True)


def test_without_an_overlay_the_selected_config_is_unchanged(tmp_path):
    """Single-directory mode: --config replaces discovery, so the repository's
    own config is not read at all, and nothing is layered."""
    _project(tmp_path, {"fail_on_findings": False, "project_name": "repo"})
    operator = _operator(tmp_path, {"fail_on_incomplete_scanners": False})

    config = resolve_config(config_path=operator, source_dir=tmp_path / "repo")

    assert config.project_name != "repo"
    assert config.fail_on_findings is not False
    assert config.fail_on_incomplete_scanners is False
