# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A repository's own config can neither turn on an off-host reporter nor point it.

The four AWS reporters send findings off the host with the operator's
credentials. A config file inside the scanned tree (``.ash/.ash.yaml``) can
neither turn one on that the trusted base has off nor turn off one it has on, and
cannot set any of its operator-only options (config/reporter_trust.py): S3's
bucket and key prefix,
CloudWatch Logs' group and stream, Security Hub's region and account, the Bedrock
reporter's model and output files, and the rest of each reporter's
``REPORTER_DESTINATION_OPTIONS`` entry. Each is checked under the spellings of the
section a config may use (``s3-reporter`` is read as ``s3``) and of the option
(``bucket-name``), on two routes:

* the CLI route: ``resolve_config`` over the scanned directory, then the check
  that runs once the reporters' plugin package is loaded, then each reporter
  built from its section as ``ReportPhase`` builds it;
* the workspace route: a project's config resolved by
  ``workspace.execution._project_config_with_policy``, with the operator's
  config as the workspace default.

The reporters' destinations come from the trusted base, so a reporter built from
the resolved config holds the operator's values or the defaults, and the scan
warns naming each option it ignored.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
    REPORTER_ENABLED_DEFAULTS,
    confine_declared_reporter_destinations,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_aws_plugins import ASH_REPORTERS
from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

#: A value for each operator-only option that its reporter's model accepts and
#: that no default has, so a value that got through would build and show.
_REPO_VALUES: Dict[str, Any] = {
    "aws_region": "eu-west-3",
    "aws_profile": "repo-profile",
    "account_id": "000000000001",
    "bucket_name": "repo-bucket",
    "key_prefix": "repo-prefix/",
    "log_group_name": "repo-log-group",
    "log_stream_name": "repo-log-stream",
    "model_id": "repo.model-v1:0",
    "output_file": "repo-summary.md",
    "output_executive_file": "repo-executive.md",
    "output_technical_file": "repo-technical.md",
    "max_retries": 7,
    "base_delay": 2.0,
    "max_delay": 30.0,
    "include_code_snippets": True,
    "custom_prompt": "Repo prompt.",
    "exclude_scanner_types": [],
    "actionable_only": False,
    "max_findings_to_analyze": 999,
    "max_findings_per_severity": 999,
    "summarize_findings": True,
    "batch_processing": True,
    "industry_context": "Repo industry.",
    "compliance_frameworks": ["Repo framework"],
    "custom_context": "Repo context.",
    "enable_fallback_models": False,
    "add_section_headers": False,
    "output_markdown": False,
    "include_sections": ["executive_summary"],
    "exclude_sections": ["technical_analysis"],
    "group_by_severity": False,
    "archive_resolved_findings": True,
    "findings_scope": "repo-scope",
}

#: Spellings of each reporter's section that its config lookup reads as its own.
_SECTION_SPELLINGS: Dict[str, Tuple[str, ...]] = {
    "aws-security-hub": ("aws-security-hub", "AwsSecurityHub"),
    "bedrock-summary-reporter": ("bedrock-summary-reporter", "BedrockSummary"),
    "cloudwatch-logs": ("cloudwatch-logs", "CloudWatchLogs"),
    "s3": ("s3", "s3-reporter", "S3Reporter"),
}

_CASES = [
    (reporter, section, hyphenated)
    for reporter in sorted(REPORTER_ENABLED_DEFAULTS)
    for section in _SECTION_SPELLINGS[reporter]
    for hyphenated in (False, True)
]
_IDS = [f"{s}{'-hyphenated' if h else ''}" for _, s, h in _CASES]


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def _warnings(records: List[logging.LogRecord]) -> str:
    return "\n".join(r.getMessage() for r in records)


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _tree_section(reporter: str, hyphenated: bool) -> Dict[str, Any]:
    names = REPORTER_DESTINATION_OPTIONS[reporter]
    options = {
        (name.replace("_", "-") if hyphenated else name): _REPO_VALUES[name]
        for name in names
    }
    return {"enabled": True, "options": options}


def _reporter_class(reporter: str) -> type:
    return next(c for c in ASH_REPORTERS if plugin_config_key(c) == reporter)


def _operator_off(tmp_path: Path, reporter: str) -> Path:
    return _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {reporter: {"enabled": False}}},
    )


def _assert_confined(config, reporter, section, hyphenated, log, root: Path):
    """Nothing the tree set is left, and the reporter, built from its section as
    ``ReportPhase`` builds it, holds none of it."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    found = config.get_plugin_config("reporter", reporter) or {}
    options = dict(found.get("options") or {})
    for name in REPORTER_DESTINATION_OPTIONS[reporter]:
        for spelling in {name, name.replace("_", "-")}:
            assert options.get(spelling) != _REPO_VALUES[name], (spelling, options)
    context = PluginContext(
        source_dir=root / "src",
        output_dir=root / "out",
        work_dir=root / "work",
        config=AshConfig(),
    )
    built = _reporter_class(reporter)(context=context, config=found or None)
    for name in REPORTER_DESTINATION_OPTIONS[reporter]:
        if hasattr(built.config.options, name):
            assert getattr(built.config.options, name) != _REPO_VALUES[name], name
    warnings = _warnings(log)
    for name in REPORTER_DESTINATION_OPTIONS[reporter]:
        written = name.replace("_", "-") if hyphenated else name
        assert f"reporters.{section}.options.{written}" in warnings, (name, warnings)
    return found, built


def _cli(source: Path, **resolve: Any):
    config = resolve_config(source_dir=source, **resolve)
    confine_declared_reporter_destinations(config, ASH_REPORTERS)
    return config


def _workspace(
    tmp_path: Path, project_config: Path, operator: Path | None, **settings: Any
):
    from automated_security_helper.config.resolve_config import (
        operator_config_digest,
    )
    from automated_security_helper.workspace.execution import (
        ProjectScanSettings,
        _project_config_with_policy,
    )
    from automated_security_helper.workspace.plan import ProjectPlan
    from automated_security_helper.workspace.resolver import _operator_config

    scan_settings = ProjectScanSettings(
        output_dir=tmp_path / "out",
        default_config_path=operator.as_posix() if operator else None,
        **settings,
    )
    # The project has a config of its own, so the plan records the operator's
    # config layered over it and that file's digest, as resolve_workspace does.
    layered = _operator_config(
        operator,
        Path(scan_settings.trusted_config_path)
        if scan_settings.trusted_config_path
        else None,
    )
    project_dir = project_config.parent.parent
    project = ProjectPlan(
        key="api",
        relative_path=project_dir.name,
        path=project_dir.as_posix(),
        label="api",
        display_label="api",
        severity_threshold="MEDIUM",
        config_source=project_config.as_posix(),
        operator_config=layered.as_posix() if layered else None,
        operator_config_digest=operator_config_digest(layered) if layered else None,
    )
    config = _project_config_with_policy(project, scan_settings)
    confine_declared_reporter_destinations(config, ASH_REPORTERS)
    return config


def test_every_operator_only_option_has_a_value_here():
    assert {n for names in REPORTER_DESTINATION_OPTIONS.values() for n in names} <= set(
        _REPO_VALUES
    )


@pytest.mark.parametrize("reporter,section,hyphenated", _CASES, ids=_IDS)
def test_the_cli_route_keeps_the_trees_destinations_and_off_switch(
    tmp_path, ash_log, reporter, section, hyphenated
):
    repo = tmp_path / "workspace" / "repo"
    project = _write(
        repo / ".ash" / ".ash.yaml",
        {"reporters": {section: _tree_section(reporter, hyphenated)}},
    )

    config = _cli(
        repo,
        config_path=project,
        trusted_config_path=_operator_off(tmp_path, reporter),
    )

    found, built = _assert_confined(
        config, reporter, section, hyphenated, ash_log, tmp_path / "context"
    )
    assert found.get("enabled") is False
    assert built.config.enabled is False
    assert f"reporters.{section}.enabled" in _warnings(ash_log)


@pytest.mark.parametrize("reporter,section,hyphenated", _CASES, ids=_IDS)
def test_the_cli_route_with_no_operator_config_keeps_the_trees_destinations(
    tmp_path, ash_log, reporter, section, hyphenated
):
    """The reporter's own default decides whether it runs; the tree points nothing."""
    repo = tmp_path / "workspace" / "repo"
    _write(
        repo / ".ash" / ".ash.yaml",
        {"reporters": {section: _tree_section(reporter, hyphenated)}},
    )

    config = _cli(repo)

    _, built = _assert_confined(
        config, reporter, section, hyphenated, ash_log, tmp_path / "context"
    )
    assert built.config.enabled is REPORTER_ENABLED_DEFAULTS[reporter]


@pytest.mark.parametrize("reporter,section,hyphenated", _CASES, ids=_IDS)
def test_the_workspace_route_keeps_the_trees_destinations_and_off_switch(
    tmp_path, ash_log, reporter, section, hyphenated
):
    """The operator's config is merged over the project's, final per field, so its
    ``enabled: false`` replaces the tree's ``true`` in that merge, silently, as
    every field the operator sets does: the reporter is off and no ``enabled``
    warning names the tree. Its destination options are confined and named."""
    project = _write(
        tmp_path / "workspace" / "api" / ".ash" / ".ash.yaml",
        {"reporters": {section: _tree_section(reporter, hyphenated)}},
    )

    config = _workspace(tmp_path, project, _operator_off(tmp_path, reporter))

    found, built = _assert_confined(
        config, reporter, section, hyphenated, ash_log, tmp_path / "context"
    )
    assert found.get("enabled") is False
    assert built.config.enabled is False
    named = [w for w in _warnings(ash_log).splitlines() if re.search(r"\.enabled\b", w)]
    assert not named, named


@pytest.mark.parametrize("reporter,section,hyphenated", _CASES, ids=_IDS)
def test_the_workspace_routes_warning_quotes_the_trees_section_spelling(
    tmp_path, ash_log, reporter, section, hyphenated
):
    """The operator's config is merged over the project's, final per field, and a
    section both write is kept under the operator's spelling. The warning names the
    project's file, so it quotes the section as that file spelled it."""
    project = _write(
        tmp_path / "workspace" / "api" / ".ash" / ".ash.yaml",
        {"reporters": {section: _tree_section(reporter, hyphenated)}},
    )

    _workspace(tmp_path, project, _operator_off(tmp_path, reporter))

    warnings = _warnings(ash_log)
    for name in REPORTER_DESTINATION_OPTIONS[reporter]:
        written = name.replace("_", "-") if hyphenated else name
        assert f"reporters.{section}.options.{written}" in warnings, (name, warnings)


#: A destination the operator's config sets for each reporter, so the test can
#: tell it from the reporter's default.
_OPERATOR_DESTINATIONS: Dict[str, Tuple[str, Any]] = {
    "aws-security-hub": ("account_id", "000000000002"),
    "bedrock-summary-reporter": ("model_id", "operator.model-v1:0"),
    "cloudwatch-logs": ("log_group_name", "operator-log-group"),
    "s3": ("bucket_name", "operator-bucket"),
}


def _built(config, reporter: str, root: Path):
    """The reporter built from ``config`` as ``ReportPhase`` builds it."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    context = PluginContext(
        source_dir=root / "src",
        output_dir=root / "out",
        work_dir=root / "work",
        config=AshConfig(),
    )
    found = config.get_plugin_config("reporter", reporter)
    return _reporter_class(reporter)(context=context, config=found)


def _null_section_configs(tmp_path: Path, reporter: str, section: str, on: bool):
    """The CLI and workspace routes' configs for a tree that writes the section as null."""
    name, value = _OPERATOR_DESTINATIONS[reporter]
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {reporter: {"enabled": on, "options": {name: value}}}},
    )
    repo = tmp_path / "workspace" / "repo"
    project = _write(repo / ".ash" / ".ash.yaml", {"reporters": {section: None}})
    return (
        _cli(repo, config_path=project, trusted_config_path=operator),
        _workspace(tmp_path, project, operator),
    )


@pytest.mark.parametrize("on", [False, True], ids=["operator-off", "operator-on"])
@pytest.mark.parametrize(
    "reporter,section",
    [(r, s) for r in sorted(REPORTER_ENABLED_DEFAULTS) for s in _SECTION_SPELLINGS[r]],
)
def test_a_null_section_in_the_tree_reads_as_an_empty_one(
    tmp_path, reporter, section, on
):
    """Left null, the section would build the reporter from its defaults: on, and
    pointed at the defaults' destination rather than the operator's."""
    name, value = _OPERATOR_DESTINATIONS[reporter]

    for config in _null_section_configs(tmp_path, reporter, section, on):
        built = _built(config, reporter, tmp_path / "context")
        assert built.config.enabled is on
        assert getattr(built.config.options, name) == value


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
def test_a_tree_config_without_the_section_keeps_the_operators_options(
    tmp_path, ash_log, reporter
):
    """A tree config replaces the operator's, so leaving the section out would
    drop every option the operator set: where findings go, what is sent, and how
    long the reporter retries. Each listed option is set to a value no default
    has."""
    names = REPORTER_DESTINATION_OPTIONS[reporter]
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {reporter: {"options": {n: _REPO_VALUES[n] for n in names}}}},
    )
    repo = tmp_path / "workspace" / "repo"
    project = _write(repo / ".ash" / ".ash.yaml", {"project_name": "repo"})

    for config in (
        _cli(repo, config_path=project, trusted_config_path=operator),
        _workspace(tmp_path, project, operator),
    ):
        options = (config.get_plugin_config("reporter", reporter) or {}).get("options")
        assert options == {n: _REPO_VALUES[n] for n in names}, options
        built = _built(config, reporter, tmp_path / "context")
        for name in names:
            if hasattr(built.config.options, name):
                assert getattr(built.config.options, name) == _REPO_VALUES[name], name
    # Nothing the tree wrote was ignored.
    assert f"reporters.{reporter}" not in _warnings(ash_log)


def _operator_on(tmp_path: Path, reporter: str) -> Path:
    return _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {reporter: {"enabled": True}}},
    )


@pytest.mark.parametrize(
    "reporter,section",
    [(r, s) for r in sorted(REPORTER_ENABLED_DEFAULTS) for s in _SECTION_SPELLINGS[r]],
)
def test_neither_route_lets_the_tree_turn_one_off(tmp_path, ash_log, reporter, section):
    """Whether it runs is the operator's in both directions: the tree's
    ``enabled: false`` is ignored with a warning, as its ``true`` is."""
    operator = _operator_on(tmp_path, reporter)
    repo = tmp_path / "workspace" / "repo"
    project = _write(
        repo / ".ash" / ".ash.yaml", {"reporters": {section: {"enabled": False}}}
    )

    for config in (
        _cli(repo, config_path=project, trusted_config_path=operator),
        _workspace(tmp_path, project, operator),
    ):
        assert _built(config, reporter, tmp_path / "context").config.enabled is True
    assert f"reporters.{section}.enabled" in _warnings(ash_log)


def _client_rules():
    """The rules of a profile that lets a client override anything it may."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.client_config_policy import rules_from

    return rules_from(
        AshConfig.model_validate(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {"enabled": True, "allowed_paths": ["/**"]}
                    }
                }
            }
        )
    )


@pytest.mark.parametrize("on", [True, False], ids=["operator-on", "operator-off"])
@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
def test_a_clients_workspace_override_does_not_choose_whether_one_runs(
    tmp_path, ash_log, reporter, on
):
    """The MCP workspace tools' config_overrides are the client's: neither an
    ``enabled: false`` nor an ``enabled: true`` in them takes effect."""
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {reporter: {"enabled": on}}},
    )
    project = _write(
        tmp_path / "workspace" / "api" / ".ash" / ".ash.yaml", {"project_name": "api"}
    )

    config = _workspace(
        tmp_path,
        project,
        operator,
        config_overrides=(f"reporters.{reporter}.enabled={str(not on).lower()}",),
        client_config_rules=_client_rules(),
    )

    assert _built(config, reporter, tmp_path / "context").config.enabled is on
    assert f"reporters.{reporter}.enabled" in _warnings(ash_log)


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
def test_the_operators_workspace_override_turns_one_off(tmp_path, ash_log, reporter):
    """On the CLI the overrides are the operator's, and turn the reporter off."""
    project = _write(
        tmp_path / "workspace" / "api" / ".ash" / ".ash.yaml",
        {"reporters": {reporter: {"enabled": True}}},
    )

    config = _workspace(
        tmp_path,
        project,
        _operator_on(tmp_path, reporter),
        config_overrides=(f"reporters.{reporter}.enabled=false",),
    )

    assert _built(config, reporter, tmp_path / "context").config.enabled is False
    assert f"reporters.{reporter}.enabled" not in _warnings(ash_log)


@pytest.mark.parametrize("value", ["disabled", "maybe", 2, None])
@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
def test_an_operator_enabled_the_model_refuses_reads_as_off(
    tmp_path, monkeypatch, ash_log, reporter, value
):
    """ASH_CONFIG's ``enabled: disabled`` cannot build the reporter, so the
    operator did not turn it on, and a tree's ``enabled: true`` does not either."""
    name, destination = _OPERATOR_DESTINATIONS[reporter]
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"reporters": {reporter: {"enabled": value, "options": {name: destination}}}},
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    repo = tmp_path / "workspace" / "repo"
    project = _write(
        repo / ".ash" / ".ash.yaml", {"reporters": {reporter: {"enabled": True}}}
    )

    for config in (_cli(repo), _workspace(tmp_path, project, operator)):
        built = _built(config, reporter, tmp_path / "context")
        assert built.config.enabled is False
    assert f"reporters.{reporter}.enabled" in _warnings(ash_log)


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
def test_off_by_default_neither_route_lets_the_tree_turn_one_on(
    tmp_path, ash_log, monkeypatch, reporter
):
    """Stands in for reporters that default to off: the tree's true loses. The
    reporters' models are held equal to the table, so the check that runs once
    they are loaded reads the same stand-in."""
    from automated_security_helper.config import reporter_trust

    monkeypatch.setitem(REPORTER_ENABLED_DEFAULTS, reporter, False)
    declared = reporter_trust.declared_enabled_defaults
    monkeypatch.setattr(
        reporter_trust,
        "declared_enabled_defaults",
        lambda classes: {
            key: REPORTER_ENABLED_DEFAULTS.get(key, value)
            for key, value in declared(classes).items()
        },
    )
    repo = tmp_path / "workspace" / "repo"
    project = _write(
        repo / ".ash" / ".ash.yaml",
        {"reporters": {reporter: _tree_section(reporter, False)}},
    )

    for config in (_cli(repo), _workspace(tmp_path, project, None)):
        found = config.get_plugin_config("reporter", reporter) or {}
        assert found.get("enabled") is False, found
    assert f"reporters.{reporter}.enabled" in _warnings(ash_log)
