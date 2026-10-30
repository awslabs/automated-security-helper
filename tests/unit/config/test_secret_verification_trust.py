# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which config sources may turn on detect-secrets' secret verification.

``resolve_config`` decides it from the same tiers as the sandbox grants
(``config/sandbox_grants.py``): a config built from a file the scanned repository or
an MCP client wrote cannot, unless the operator's trusted base or
``--config-overrides`` names the filter as well. These tests read the resolved
config only; the scans that show no request is sent are in
``tests/unit/plugin_modules/ash_builtin/test_detect_secrets_verification_trust.py``.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.config import sandbox_grants
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.secret_verification_trust import (
    is_verification_filter,
    names_verification,
)

pytestmark = pytest.mark.unit

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
VERIFYING_SETTINGS = {
    "version": "1.5.0",
    "plugins_used": [{"name": "AWSKeyDetector"}],
    "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}],
}
VERIFICATION_OVERRIDE = (
    "scanners.detect-secrets.options.scan_settings.filters_used+="
    + json.dumps([{"path": VERIFICATION_FILTER, "min_level": 2}])
)


def _config_file(path: Path, settings: dict | None) -> Path:
    options = {} if settings is None else {"scan_settings": settings}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "project_name": "verification",
                "scanners": {"detect-secrets": {"enabled": True, "options": options}},
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture(autouse=True)
def _outside_every_checkout(tmp_path, monkeypatch):
    assert not sandbox_grants.in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)


@pytest.fixture
def repo(tmp_path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def _record(config):
    return config._untrusted_detect_secrets_settings


@pytest.mark.parametrize(
    "path",
    [
        VERIFICATION_FILTER,
        "file:///opt/tools/filters.py::is_ignored_due_to_verification_policies",
        "file:///opt/tools/filters.py:: is_ignored_due_to_verification_policies ",
        # The scheme is read as is_file_entry reads it: case and padding ignored.
        "FILE:///opt/tools/filters.py::is_ignored_due_to_verification_policies",
        "  file:///opt/tools/filters.py::is_ignored_due_to_verification_policies",
    ],
)
def test_both_spellings_of_the_filter_are_recognized(path):
    assert is_verification_filter(path)


@pytest.mark.parametrize(
    "path",
    [
        "detect_secrets.filters.heuristic.is_likely_id_string",
        "file:///opt/tools/filters.py::is_ignored_due_to_verification",
        "file:///opt/is_ignored_due_to_verification_policies.py",
        "FILE:///opt/tools/filters.py::is_likely_id_string",
        None,
    ],
)
def test_other_filters_are_not_taken_for_it(path):
    assert not is_verification_filter(path)


def test_a_repository_config_cannot_turn_verification_on(repo):
    _config_file(repo / ".ash" / ".ash.yaml", VERIFYING_SETTINGS)

    config = resolve_config(source_dir=repo)

    assert not names_verification(config)
    assert _record(config) is not None
    assert ".ash.yaml" in _record(config).reason
    assert _record(config).operator_verifies is False


def test_a_repository_config_is_refused_even_without_the_filter(repo):
    """The record also covers baselines the config leads the scanner to."""
    _config_file(repo / ".ash" / ".ash.yaml", None)

    config = resolve_config(source_dir=repo)

    assert _record(config) is not None


def test_an_mcp_client_config_cannot_turn_verification_on(repo, tmp_path):
    """Refused, naming the setting: detect-secrets' section is denied whole to a
    client, as it sends candidate secrets off the host (ALWAYS_DENIED_PATHS)."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    delivered = _config_file(tmp_path / "delivered" / "ash.yaml", VERIFYING_SETTINGS)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(config_path=delivered, source_dir=repo, untrusted_config=True)

    assert "scanners.detect-secrets" in str(refused.value)


def test_an_operator_config_outside_the_tree_turns_it_on(repo, tmp_path):
    operator = _config_file(tmp_path / "operator" / "ash.yaml", VERIFYING_SETTINGS)

    config = resolve_config(config_path=operator, source_dir=repo)

    assert names_verification(config)
    assert _record(config) is None


def test_no_config_file_at_all_is_the_operators(repo):
    config = resolve_config(source_dir=repo)

    assert _record(config) is None


def test_config_overrides_are_the_operators(repo):
    """--config-overrides can turn it on over a repository config, as it can grant
    sandbox access over one."""
    _config_file(repo / ".ash" / ".ash.yaml", VERIFYING_SETTINGS)

    config = resolve_config(source_dir=repo, config_overrides=[VERIFICATION_OVERRIDE])

    assert names_verification(config)
    assert _record(config).operator_verifies is True


def test_an_unrelated_override_does_not_turn_it_on(repo):
    _config_file(repo / ".ash" / ".ash.yaml", VERIFYING_SETTINGS)

    config = resolve_config(
        source_dir=repo,
        config_overrides=["scanners.detect-secrets.options.scan_timeout=60"],
    )

    assert not names_verification(config)
    assert _record(config).operator_verifies is False


def test_the_operators_default_config_decides_for_a_projects_own_config(repo, tmp_path):
    """Workspace mode: a project's own config replaces the operator's default config,
    which still decides, as it does for the sandbox grants."""
    project_config = _config_file(repo / ".ash" / ".ash.yaml", VERIFYING_SETTINGS)
    operator_default = _config_file(
        tmp_path / "operator" / "default.yaml", VERIFYING_SETTINGS
    )

    config = resolve_config(
        config_path=project_config,
        source_dir=repo,
        trusted_config_path=operator_default,
    )

    assert names_verification(config)
    assert _record(config).operator_verifies is True


def test_an_operator_default_config_without_the_filter_refuses_it(repo, tmp_path):
    project_config = _config_file(repo / ".ash" / ".ash.yaml", VERIFYING_SETTINGS)
    operator_default = _config_file(tmp_path / "operator" / "default.yaml", None)

    config = resolve_config(
        config_path=project_config,
        source_dir=repo,
        trusted_config_path=operator_default,
    )

    assert not names_verification(config)
    assert _record(config).operator_verifies is False


def test_an_override_naming_a_baseline_records_it_as_the_operators(repo, tmp_path):
    _config_file(repo / ".ash" / ".ash.yaml", None)
    outside = tmp_path / "shared" / "verifying.baseline"

    config = resolve_config(
        source_dir=repo,
        config_overrides=[
            f"scanners.detect-secrets.options.baseline_file={outside.as_posix()}"
        ],
    )

    assert _record(config).operator_baseline == outside.as_posix()


FILE_SETTINGS = {
    "version": "1.5.0",
    "plugins_used": [
        {"name": "AWSKeyDetector"},
        {"name": "AnyPlugin", "path": "file:///opt/any/module.py"},
    ],
    "filters_used": [{"path": "file:///opt/any/module.py::anyfilter"}],
}


def _file_paths(config):
    settings = config.scanners.detect_secrets.options.scan_settings
    return [
        getattr(item, "path", None)
        for item in [*settings.plugins_used, *settings.filters_used]
        if getattr(item, "path", None)
    ]


def test_a_repository_config_names_no_plugin_or_filter_file(repo):
    _config_file(repo / ".ash" / ".ash.yaml", FILE_SETTINGS)

    config = resolve_config(source_dir=repo)

    assert _file_paths(config) == []
    plugins = config.scanners.detect_secrets.options.scan_settings.plugins_used
    assert [plugin.name for plugin in plugins] == ["AWSKeyDetector"]


def test_a_file_the_operator_names_too_is_kept(repo, tmp_path):
    _config_file(repo / ".ash" / ".ash.yaml", FILE_SETTINGS)
    operator_default = _config_file(
        tmp_path / "operator" / "default.yaml", FILE_SETTINGS
    )

    config = resolve_config(
        config_path=repo / ".ash" / ".ash.yaml",
        source_dir=repo,
        trusted_config_path=operator_default,
    )

    assert _file_paths(config) == [
        "file:///opt/any/module.py",
        "file:///opt/any/module.py::anyfilter",
    ]


def test_an_operator_config_keeps_its_plugin_and_filter_files(repo, tmp_path):
    operator = _config_file(tmp_path / "operator" / "ash.yaml", FILE_SETTINGS)

    config = resolve_config(config_path=operator, source_dir=repo)

    assert len(_file_paths(config)) == 2
