# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporter destinations, regions and credentials in the scanned tree's config are ignored.

The AWS reporters send findings to a service in an account, region, bucket, log
group or model that their options name, with the credentials their profile option
picks, and the Bedrock reporter writes its summaries to the files its options
name. When the config was built from a file inside the scanned tree, those options
come only from the trusted base (the defaults, an operator config outside the
tree, and ``--config-overrides``). See config/reporter_trust.py.
"""

import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
    REPORTER_ENABLED_DEFAULTS,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.config._client_policy_helpers import (
    narrow_client_rules as _narrow_client_rules,
)
from tests.utils.helpers import mark_git_checkout

#: Values that read like what a repository would write, for some options, each of
#: the type its options model validates and none of them a default. Every other
#: option is a string, and gets ``repo-<name>``, which no default is.
_EXAMPLE_VALUES: Dict[str, Any] = {
    # A real region name: the options models refuse anything else.
    "aws_region": "eu-west-3",
    "account_id": "000000000001",
    # Plain file names: a path is replaced by the options' own validation from
    # any source, which would satisfy these tests without the destination check.
    "output_file": "repo-summary.md",
    "output_executive_file": "repo-executive.md",
    "output_technical_file": "repo-technical.md",
    "max_retries": 7,
    "base_delay": 2.0,
    "max_delay": 30.0,
    "include_code_snippets": True,
    "exclude_scanner_types": [],
    "actionable_only": False,
    "max_findings_to_analyze": 999,
    "max_findings_per_severity": 999,
    "summarize_findings": True,
    "batch_processing": True,
    "compliance_frameworks": ["Repo framework"],
    "enable_fallback_models": False,
    "add_section_headers": False,
    "output_markdown": False,
    "include_sections": ["executive_summary"],
    "exclude_sections": ["technical_analysis"],
    "group_by_severity": False,
    "archive_resolved_findings": True,
}

# Every option listed in config/reporter_trust.py, with a value no default has.
# Derived from the table, so an option added there is covered here.
REPO_VALUES: Dict[str, Dict[str, Any]] = {
    reporter: {name: _EXAMPLE_VALUES.get(name, f"repo-{name}") for name in names}
    for reporter, names in REPORTER_DESTINATION_OPTIONS.items()
}


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _warnings(records: List[logging.LogRecord]) -> List[str]:
    return [r.getMessage() for r in records if r.levelno >= logging.WARNING]


def _write_config(path: Path, reporters: dict, **extra) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {"project_name": "scanned", "reporters": reporters, **extra}
    path.write_text(yaml.safe_dump(document))
    return path


def _options(config, key: str) -> dict:
    found = config.get_plugin_config("reporter", key) or {}
    return dict(found.get("options") or {})


@pytest.mark.parametrize("reporter", sorted(REPO_VALUES))
@pytest.mark.unit
def test_an_in_tree_config_does_not_choose_a_reporters_destination(
    tmp_path, ash_log, reporter
):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {reporter: {"options": dict(REPO_VALUES[reporter])}},
    )

    config = resolve_config(source_dir=source)

    options = _options(config, reporter)
    for name, value in REPO_VALUES[reporter].items():
        assert options.get(name) != value, (reporter, name, options)
    warnings = "\n".join(_warnings(ash_log))
    for name in REPO_VALUES[reporter]:
        assert f"reporters.{reporter}.options.{name}" in warnings, warnings


@pytest.mark.parametrize("name", ["archive_resolved_findings", "findings_scope"])
@pytest.mark.unit
def test_security_hubs_import_scope_and_archiving_are_the_operators(
    tmp_path, ash_log, name
):
    """Which findings the reporter imports and archives decides what the account sees."""
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {"aws-security-hub": {"options": {name: "repo-value"}}},
    )

    config = resolve_config(source_dir=source)

    assert name not in _options(config, "aws-security-hub")
    warnings = "\n".join(_warnings(ash_log))
    assert f"reporters.aws-security-hub.options.{name}" in warnings, warnings


#: What the Bedrock reporter sends to the model with the findings, which
#: findings and how many, and which of its calls are made, each with a value
#: other than its default.
_BEDROCK_CONTENT = {
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
}


@pytest.mark.parametrize("name", sorted(_BEDROCK_CONTENT))
@pytest.mark.unit
def test_a_repository_config_does_not_choose_what_bedrock_is_sent(
    tmp_path, ash_log, name
):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {"bedrock-summary-reporter": {"options": {name: _BEDROCK_CONTENT[name]}}},
    )

    config = resolve_config(source_dir=source)

    assert name not in _options(config, "bedrock-summary-reporter")
    warnings = "\n".join(_warnings(ash_log))
    assert f"reporters.bedrock-summary-reporter.options.{name}" in warnings, warnings


@pytest.mark.parametrize("name", sorted(_BEDROCK_CONTENT))
@pytest.mark.parametrize(
    "section",
    ["bedrock-summary-reporter", "BedrockSummary", "bedrock_summary_reporter"],
)
@pytest.mark.unit
def test_a_hyphenated_spelling_of_a_bedrock_option_is_ignored_too(
    tmp_path, ash_log, name, section
):
    """``-`` and ``_`` are the same key to a config merge, so both are confined."""
    spelled = name.replace("_", "-")
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {section: {"options": {spelled: _BEDROCK_CONTENT[name]}}},
    )

    config = resolve_config(source_dir=source)

    options = _options(config, "bedrock-summary-reporter")
    assert spelled not in options and name not in options, options
    warnings = "\n".join(_warnings(ash_log))
    assert f"reporters.{section}.options.{spelled}" in warnings, warnings


@pytest.mark.parametrize("name", sorted(_BEDROCK_CONTENT))
@pytest.mark.unit
def test_a_repository_config_repeating_the_operators_bedrock_content_applies(
    tmp_path, ash_log, name
):
    """The same value is no change: it applies, with no warning."""
    section = {"bedrock-summary-reporter": {"options": {name: _BEDROCK_CONTENT[name]}}}
    source = tmp_path / "repo"
    project = _write_config(source / ".ash" / ".ash.yaml", section)
    operator = _write_config(tmp_path / "operator" / "ash.yaml", section)

    config = resolve_config(
        config_path=project, source_dir=source, trusted_config_path=operator
    )

    assert _options(config, "bedrock-summary-reporter")[name] == _BEDROCK_CONTENT[name]
    assert not any(name in message for message in _warnings(ash_log))


#: The AWS reporters whose options model has retry options, and those options.
_RETRYING = ("aws-security-hub", "bedrock-summary-reporter", "cloudwatch-logs", "s3")
_RETRY_OPTIONS = ("max_retries", "base_delay", "max_delay")
_RETRY_CASES = [(r, n) for r in _RETRYING for n in _RETRY_OPTIONS]


@pytest.mark.parametrize(
    "reporter,name", _RETRY_CASES, ids=[f"{r}.{n}" for r, n in _RETRY_CASES]
)
@pytest.mark.unit
def test_a_repository_config_does_not_tune_a_reporters_retries(
    tmp_path, ash_log, reporter, name
):
    """How long a reporter keeps calling AWS with the operator's credentials."""
    source = tmp_path / "repo"
    _write_config(source / ".ash" / ".ash.yaml", {reporter: {"options": {name: 7}}})

    config = resolve_config(source_dir=source)

    assert name not in _options(config, reporter)
    warnings = "\n".join(_warnings(ash_log))
    assert f"reporters.{reporter}.options.{name}" in warnings, warnings


_TABLE_CASES = [
    (reporter, name)
    for reporter, names in sorted(REPORTER_DESTINATION_OPTIONS.items())
    for name in names
]


@pytest.mark.parametrize(
    "reporter,name", _TABLE_CASES, ids=[f"{r}.{n}" for r, n in _TABLE_CASES]
)
@pytest.mark.unit
def test_a_repository_config_repeating_the_operators_value_applies(
    tmp_path, ash_log, reporter, name
):
    """The same value is no change: it applies, with no warning, and the reporter
    built from the section holds it."""
    from automated_security_helper.base.plugin_config import plugin_config_key
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        ASH_REPORTERS,
    )

    value = REPO_VALUES[reporter][name]
    section = {reporter: {"options": {name: value}}}
    source = tmp_path / "repo"
    project = _write_config(source / ".ash" / ".ash.yaml", section)
    operator = _write_config(tmp_path / "operator" / "ash.yaml", section)

    config = resolve_config(
        config_path=project, source_dir=source, trusted_config_path=operator
    )

    assert _options(config, reporter)[name] == value
    assert not any(name in message for message in _warnings(ash_log))
    reporter_class = next(c for c in ASH_REPORTERS if plugin_config_key(c) == reporter)
    built = reporter_class(
        context=PluginContext(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "work",
            config=AshConfig(),
        ),
        config=config.get_plugin_config("reporter", reporter),
    )
    if hasattr(built.config.options, name):
        assert getattr(built.config.options, name) == value


@pytest.mark.parametrize(
    "spelling", ["BedrockSummary", "bedrocksummaryreporter", "Bedrock_Summary_Reporter"]
)
@pytest.mark.unit
def test_another_spelling_of_the_reporters_section_is_covered(
    tmp_path, ash_log, spelling
):
    """get_plugin_config reads each of these as bedrock-summary-reporter's section."""
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {spelling: {"options": {"aws_region": "repo-region-1"}}},
    )

    config = resolve_config(source_dir=source)

    assert _options(config, "bedrock-summary-reporter").get("aws_region") != (
        "repo-region-1"
    )
    assert any("aws_region" in message for message in _warnings(ash_log))


@pytest.mark.unit
def test_other_reporter_options_in_the_tree_still_apply(tmp_path, ash_log):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {
            "bedrock-summary-reporter": {
                "options": {
                    "summary_style": "technical",
                    "aws_region": "repo-region-1",
                },
            },
            "s3": {"options": {"file_format": "yaml"}},
            "markdown": {"options": {"compact": True}},
        },
    )

    config = resolve_config(source_dir=source)

    bedrock = config.get_plugin_config("reporter", "bedrock-summary-reporter")
    assert bedrock["options"]["summary_style"] == "technical"
    assert _options(config, "s3")["file_format"] == "yaml"
    assert config.reporters.markdown.options.compact is True


@pytest.mark.unit
def test_no_warning_when_the_tree_sets_no_destination(tmp_path, ash_log):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml", {"s3": {"options": {"file_format": "yaml"}}}
    )

    resolve_config(source_dir=source)

    assert not any("reporters." in message for message in _warnings(ash_log))


@pytest.mark.unit
def test_an_operator_config_outside_the_tree_is_honored(tmp_path, ash_log):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {"s3": {"options": {"bucket_name": "repo-bucket"}}},
    )
    operator = _write_config(
        tmp_path / "operator" / "ash.yaml",
        {"s3": {"options": {"bucket_name": "operator-bucket"}}},
    )

    config = resolve_config(config_path=operator, source_dir=source)

    assert _options(config, "s3")["bucket_name"] == "operator-bucket"
    assert not _warnings(ash_log)


@pytest.mark.unit
def test_an_operator_default_config_replaced_by_the_tree_supplies_the_value(
    tmp_path, ash_log
):
    """Workspace mode: the project's own config replaces the operator's."""
    source = tmp_path / "repo"
    project = _write_config(
        source / ".ash" / ".ash.yaml",
        {"s3": {"options": {"bucket_name": "repo-bucket"}}},
    )
    operator = _write_config(
        tmp_path / "operator" / "ash.yaml",
        {"s3": {"options": {"bucket_name": "operator-bucket"}}},
    )

    config = resolve_config(
        config_path=project, source_dir=source, trusted_config_path=operator
    )

    assert _options(config, "s3")["bucket_name"] == "operator-bucket"


@pytest.mark.unit
def test_config_overrides_are_honored(tmp_path, ash_log):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {"s3": {"options": {"bucket_name": "repo-bucket"}}},
    )

    config = resolve_config(
        source_dir=source,
        config_overrides=["reporters.s3.options.bucket_name=operator-bucket"],
    )

    assert _options(config, "s3")["bucket_name"] == "operator-bucket"
    assert not any("bucket_name" in message for message in _warnings(ash_log))


def _enabled(config, reporter: str):
    """Whether ``reporter`` runs under ``config``: its section's value, or its default."""
    section = config.get_plugin_config("reporter", reporter) or {}
    return section.get("enabled", REPORTER_ENABLED_DEFAULTS[reporter])


def _operator(tmp_path: Path, reporter: str, enabled: bool) -> Path:
    return _write_config(
        tmp_path / "operator" / "ash.yaml", {reporter: {"enabled": enabled}}
    )


def _operator_off(tmp_path: Path, reporter: str) -> Path:
    return _operator(tmp_path, reporter, False)


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_an_in_tree_config_does_not_turn_on_a_reporter_the_operator_turned_off(
    tmp_path, ash_log, reporter
):
    """Each of these sends findings off the host, so running it is the operator's choice."""
    source = tmp_path / "repo"
    project = _write_config(
        source / ".ash" / ".ash.yaml", {reporter: {"enabled": True}}
    )

    config = resolve_config(
        config_path=project,
        source_dir=source,
        trusted_config_path=_operator_off(tmp_path, reporter),
    )

    assert _enabled(config, reporter) is False
    warnings = "\n".join(_warnings(ash_log))
    assert f"reporters.{reporter}.enabled" in warnings, warnings


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_an_in_tree_config_that_leaves_the_reporter_out_keeps_it_off(
    tmp_path, ash_log, reporter
):
    """The tree's config replaces the operator's, and leaving a section out would
    return the reporter to its own default; the operator's off still holds."""
    source = tmp_path / "repo"
    project = _write_config(
        source / ".ash" / ".ash.yaml", {"markdown": {"enabled": True}}
    )

    config = resolve_config(
        config_path=project,
        source_dir=source,
        trusted_config_path=_operator_off(tmp_path, reporter),
    )

    assert _enabled(config, reporter) is False
    assert not any("enabled" in message for message in _warnings(ash_log))


def _ops_config(where: Path) -> Path:
    """A config that turns the S3 reporter on and names its bucket."""
    return _write_config(
        where / "ash.yaml",
        {"s3": {"enabled": True, "options": {"bucket_name": "ops-bucket"}}},
    )


@pytest.mark.unit
def test_an_ash_config_in_another_checkout_neither_turns_on_nor_points_a_reporter(
    tmp_path, ash_log, monkeypatch
):
    """A file in any git checkout, not only the scanned one, is one someone else
    can push to (sandbox_grants.repository_written): its reporter choices are
    replaced by the trusted base's, with the remedy that keeps them. Named by
    ASH_CONFIG here; the same file named with --config is covered end to end in
    tests/unit/plugin_modules/ash_aws_plugins/
    test_scanned_repository_config_cannot_send_off_host.py."""
    from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING

    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    monkeypatch.setenv("ASH_CONFIG", str(_ops_config(ops / "ash")))
    source = tmp_path / "repo"
    mark_git_checkout(source)

    config = resolve_config(source_dir=source)

    assert _enabled(config, "s3") is REPORTER_ENABLED_DEFAULTS["s3"] is False
    assert _options(config, "s3").get("bucket_name") != "ops-bucket"
    named = [m for m in _warnings(ash_log) if "reporters.s3." in m]
    assert len(named) == 1, named
    assert "reporters.s3.enabled" in named[0]
    assert "reporters.s3.options.bucket_name" in named[0]
    assert named[0].endswith(KEEP_A_SETTING), named[0]


@pytest.mark.unit
def test_control_the_same_ash_config_outside_every_checkout_is_the_operators(
    tmp_path, ash_log, monkeypatch
):
    monkeypatch.setenv("ASH_CONFIG", str(_ops_config(tmp_path / "ops" / "ash")))
    source = tmp_path / "repo"
    mark_git_checkout(source)

    config = resolve_config(source_dir=source)

    assert _enabled(config, "s3") is True
    assert _options(config, "s3").get("bucket_name") == "ops-bucket"
    assert not [m for m in _warnings(ash_log) if "reporters.s3." in m]


@pytest.mark.unit
def test_the_operators_ash_config_turning_one_off_holds_too(
    tmp_path, ash_log, monkeypatch
):
    """The CLI's trusted base outside workspace mode is ASH_CONFIG's file."""
    monkeypatch.setenv("ASH_CONFIG", str(_operator_off(tmp_path, "s3")))
    source = tmp_path / "repo"
    _write_config(source / ".ash" / ".ash.yaml", {"s3": {"enabled": True}})

    config = resolve_config(source_dir=source)

    assert _enabled(config, "s3") is False
    assert any("reporters.s3.enabled" in m for m in _warnings(ash_log))


@pytest.mark.parametrize("operator", ["defaults", "operator-on"])
@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_an_in_tree_config_cannot_turn_one_off(tmp_path, ash_log, reporter, operator):
    """Whether it runs is the operator's in both directions, so the tree's
    ``enabled: false`` is ignored with a warning, as its ``true`` is. Each of
    these reporters is off by default, so with no operator setting the tree's
    ``false`` changes nothing and is not named."""
    source = tmp_path / "repo"
    project = _write_config(
        source / ".ash" / ".ash.yaml", {reporter: {"enabled": False}}
    )
    trusted = (
        {"trusted_config_path": _operator(tmp_path, reporter, True)}
        if operator == "operator-on"
        else {}
    )

    config = resolve_config(config_path=project, source_dir=source, **trusted)

    expected = (
        True if operator == "operator-on" else REPORTER_ENABLED_DEFAULTS[reporter]
    )
    assert _enabled(config, reporter) is expected
    warnings = "\n".join(_warnings(ash_log))
    assert (f"reporters.{reporter}.enabled" in warnings) is expected, warnings


@pytest.mark.parametrize("value", [0, "no", "false"])
@pytest.mark.unit
def test_a_tree_enabled_read_as_false_is_confined_too(tmp_path, ash_log, value):
    """Not only ``false`` itself: any value the reporter reads as off is the tree's
    choice too, and is ignored with a warning where the operator has it on."""
    source = tmp_path / "repo"
    project = _write_config(source / ".ash" / ".ash.yaml", {"s3": {"enabled": value}})

    config = resolve_config(
        config_path=project,
        source_dir=source,
        trusted_config_path=_operator(tmp_path, "s3", True),
    )

    assert _enabled(config, "s3") is True
    assert any("reporters.s3.enabled" in m for m in _warnings(ash_log))


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_a_tree_repeating_the_operators_off_is_not_warned(tmp_path, ash_log, reporter):
    """``enabled: false`` where the operator has the reporter off changes nothing."""
    source = tmp_path / "repo"
    project = _write_config(
        source / ".ash" / ".ash.yaml", {reporter: {"enabled": False}}
    )

    config = resolve_config(
        config_path=project,
        source_dir=source,
        trusted_config_path=_operator_off(tmp_path, reporter),
    )

    assert _enabled(config, reporter) is False
    assert not any("enabled" in message for message in _warnings(ash_log))


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_an_override_turns_one_off(tmp_path, ash_log, reporter):
    """``--config-overrides`` are the operator's, in both directions."""
    source = tmp_path / "repo"
    project = _write_config(
        source / ".ash" / ".ash.yaml", {reporter: {"enabled": True}}
    )

    config = resolve_config(
        config_path=project,
        source_dir=source,
        trusted_config_path=_operator(tmp_path, reporter, True),
        config_overrides=[f"reporters.{reporter}.enabled=false"],
    )

    assert _enabled(config, reporter) is False
    assert not any("enabled" in message for message in _warnings(ash_log))


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_enabled_true_where_the_operator_has_it_on_changes_nothing(
    tmp_path, ash_log, reporter
):
    source = tmp_path / "repo"
    project = _write_config(
        source / ".ash" / ".ash.yaml", {reporter: {"enabled": True}}
    )

    config = resolve_config(
        config_path=project,
        source_dir=source,
        trusted_config_path=_operator(tmp_path, reporter, True),
    )

    assert _enabled(config, reporter) is True
    assert not any("enabled" in message for message in _warnings(ash_log))


@pytest.mark.parametrize(
    "section",
    [None, {"options": {"file_format": "yaml"}}],
    ids=["absent", "no-enabled"],
)
@pytest.mark.unit
def test_a_reporter_off_by_its_default_gets_no_section_added(section):
    """Nothing is written for a reporter the config already leaves off."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.reporter_trust import _confine_enabled

    reporters = {} if section is None else {"s3": dict(section)}
    config = AshConfig.model_validate({"reporters": reporters})
    trusted = AshConfig.model_validate({"reporters": {"s3": {"enabled": False}}})
    before = config.model_dump(by_alias=True)

    ignored = _confine_enabled(config, trusted, {"s3": False})

    assert ignored == []
    assert config.model_dump(by_alias=True) == before


@pytest.mark.parametrize("trusted_value", ["no", 0, "false"])
@pytest.mark.unit
def test_an_operator_off_written_another_way_still_counts(tmp_path, trusted_value):
    """The operator's value is read as the reporter's model reads it."""
    source = tmp_path / "repo"
    project = _write_config(source / ".ash" / ".ash.yaml", {"s3": {"enabled": True}})
    operator = _write_config(
        tmp_path / "operator" / "ash.yaml", {"s3": {"enabled": trusted_value}}
    )

    config = resolve_config(
        config_path=project, source_dir=source, trusted_config_path=operator
    )

    assert _enabled(config, "s3") is False


@pytest.fixture
def defaults_off(monkeypatch):
    """Each off-host reporter off by its own default.

    ``REPORTER_ENABLED_DEFAULTS`` reads false for all four at this release, so
    the fixture changes nothing today; it pins the table at false so the checks
    below stay about the fallback to the trusted base, not about a default, if a
    release turns one on. ``test_each_off_host_reporters_enabled_default_is_listed``
    holds the table equal to the models, so such a release changes both.
    """
    for reporter in REPORTER_ENABLED_DEFAULTS:
        monkeypatch.setitem(REPORTER_ENABLED_DEFAULTS, reporter, False)


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_off_by_default_an_in_tree_config_cannot_enable_it(
    tmp_path, ash_log, defaults_off, reporter
):
    """No operator config: the trusted base is the defaults, which have it off."""
    source = tmp_path / "repo"
    _write_config(source / ".ash" / ".ash.yaml", {reporter: {"enabled": True}})

    config = resolve_config(source_dir=source)

    assert _enabled(config, reporter) is False
    warnings = "\n".join(_warnings(ash_log))
    assert f"reporters.{reporter}.enabled" in warnings, warnings


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_off_by_default_a_delivered_config_cannot_enable_it(
    tmp_path, ash_log, defaults_off, reporter
):
    """Refused under the default denied_paths, and under a policy whose own list
    names only ``/fail_on_findings`` (``_client_policy_helpers``) as well: a
    reporter that sends findings off the host is denied whole whatever the list
    (ALWAYS_DENIED_PATHS). The confinement on its own is covered by the in-tree
    route above."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    upload = _write_config(
        tmp_path / "upload" / "ash.yaml", {reporter: {"enabled": True}}
    )
    source = tmp_path / "repo"
    source.mkdir()

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(config_path=upload, source_dir=source, untrusted_config=True)
    assert f"reporters.{reporter}.enabled" in str(refused.value)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(
            config_path=upload,
            source_dir=source,
            untrusted_config=True,
            client_config_policy=_narrow_client_rules(),
        )
    assert f"reporters.{reporter}.enabled" in str(refused.value)


#: A section that sets an option a repository's config may still set, and no
#: ``enabled``. Security Hub's and CloudWatch Logs' options models have no such
#: option, so their sections hold an empty ``options``.
_OPTIONS_ONLY: Dict[str, dict] = {
    "s3": {"options": {"file_format": "yaml"}},
    "bedrock-summary-reporter": {"options": {"temperature": 0.1}},
    "aws-security-hub": {"options": {}},
    "cloudwatch-logs": {"options": {}},
}


@pytest.mark.unit
def test_every_off_host_reporter_has_an_options_only_section():
    assert set(_OPTIONS_ONLY) == set(REPORTER_ENABLED_DEFAULTS)


@pytest.mark.parametrize("route", ["tree", "delivered"])
@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
@pytest.mark.unit
def test_a_section_without_enabled_does_not_turn_on_a_reporter_the_operator_has_off(
    tmp_path, ash_log, reporter, route
):
    """The operator's off holds, and since the section wrote no ``enabled``,
    nothing about ``enabled`` is warned. A delivered section that sets an option
    is refused, as the reporter's whole section is denied to a client
    (ALWAYS_DENIED_PATHS); one that sets nothing is resolved."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    section = {reporter: _OPTIONS_ONLY[reporter]}
    source = tmp_path / "repo"
    source.mkdir()
    if route == "tree":
        written = _write_config(source / ".ash" / ".ash.yaml", section)
        delivered = {}
    else:
        written = _write_config(tmp_path / "upload" / "ash.yaml", section)
        delivered = {
            "untrusted_config": True,
            "client_config_policy": _narrow_client_rules(),
        }
        if _OPTIONS_ONLY[reporter]["options"]:
            with pytest.raises(
                ASHConfigFieldDeniedError, match=f"reporters.{reporter}"
            ):
                resolve_config(
                    config_path=written,
                    source_dir=source,
                    trusted_config_path=_operator_off(tmp_path, reporter),
                    **delivered,
                )
            return

    config = resolve_config(
        config_path=written,
        source_dir=source,
        trusted_config_path=_operator_off(tmp_path, reporter),
        **delivered,
    )

    assert _enabled(config, reporter) is False
    assert not any("enabled" in message for message in _warnings(ash_log))


# The scan engine over a config whose tree file turns every off-host reporter on,
# with the reporters' models patched to default off and the table left as it is,
# so only the check after the plugin package is loaded can catch it.
_ENGINE_WITH_DEFAULTS_OFF = """
import json, sys
from pathlib import Path
from automated_security_helper.plugin_modules.ash_aws_plugins import ASH_REPORTERS

for reporter in ASH_REPORTERS:
    config_model = reporter.model_fields["config"].annotation.__args__[0]
    config_model.model_fields["enabled"].default = False
    config_model.model_rebuild(force=True)

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.execution_engine import ScanExecutionEngine

source = Path(sys.argv[1])
config = resolve_config(source_dir=source)
ScanExecutionEngine(
    context=PluginContext(source_dir=source, output_dir=source.parent / "out",
                          work_dir=source.parent / "work", config=config),
    show_progress=False,
    ash_plugin_modules=["automated_security_helper.plugin_modules.ash_aws_plugins"],
)
print(json.dumps({
    name: (config.get_plugin_config("reporter", name) or {}).get("enabled")
    for name in json.loads(sys.argv[2])
}))
"""


@pytest.mark.integration
def test_off_by_their_models_default_the_loaded_reporters_stay_off(tmp_path):
    """Once the plugin package is loaded, its models' own defaults decide."""
    names = sorted(REPORTER_ENABLED_DEFAULTS)
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml", {name: {"enabled": True} for name in names}
    )

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _ENGINE_WITH_DEFAULTS_OFF,
            str(source),
            json.dumps(names),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
    )

    assert result.returncode == 0, result.stderr[-4000:]
    enabled = json.loads(result.stdout.strip().splitlines()[-1])
    assert enabled == dict.fromkeys(names, False), enabled


@pytest.mark.unit
def test_the_example_values_cover_the_table():
    """An option added to the table gets a value above without another edit."""
    assert {r: set(v) for r, v in REPO_VALUES.items()} == {
        r: set(names) for r, names in REPORTER_DESTINATION_OPTIONS.items()
    }


@pytest.mark.unit
def test_every_operator_only_reporter_setting_is_a_default_denied_path():
    """Under the MCP server a delivered file that sets one is refused."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.client_config_policy import _names

    shipped = RuntimeOverridesConfig().denied_paths
    pointers = [
        f"/reporters/{reporter}/options/{name}"
        for reporter, names in REPORTER_DESTINATION_OPTIONS.items()
        for name in names
    ] + [f"/reporters/{reporter}/enabled" for reporter in REPORTER_ENABLED_DEFAULTS]
    uncovered = [
        pointer
        for pointer in pointers
        if not any(_names(entry, pointer) for entry in shipped)
    ]
    assert not uncovered


@pytest.mark.unit
def test_an_override_turns_one_on(tmp_path, ash_log):
    source = tmp_path / "repo"
    project = _write_config(source / ".ash" / ".ash.yaml", {"s3": {"enabled": False}})

    config = resolve_config(
        config_path=project,
        source_dir=source,
        trusted_config_path=_operator_off(tmp_path, "s3"),
        config_overrides=["reporters.s3.enabled=true"],
    )

    assert _enabled(config, "s3") is True
    assert not any("enabled" in message for message in _warnings(ash_log))


@pytest.mark.unit
def test_a_base_the_tree_extends_sets_no_destination_either(tmp_path, ash_log):
    source = tmp_path / "repo"
    _write_config(
        source / "shared" / "base.yaml",
        {"s3": {"options": {"bucket_name": "base-bucket"}}},
    )
    _write_config(source / ".ash" / ".ash.yaml", {}, extends="../shared/base.yaml")

    config = resolve_config(source_dir=source)

    assert _options(config, "s3").get("bucket_name") != "base-bucket"
    assert any("bucket_name" in message for message in _warnings(ash_log))


@pytest.mark.unit
def test_a_config_inside_the_checkout_but_outside_the_source_dir(tmp_path, ash_log):
    """CLI scan of a directory in a checkout: the tree is the whole checkout."""
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    source = checkout / "services" / "api"
    source.mkdir(parents=True)
    shared = _write_config(
        checkout / "config" / "ash.yaml",
        {"cloudwatch-logs": {"options": {"log_group_name": "repo-log-group"}}},
    )

    config = resolve_config(config_path=shared, source_dir=source)

    assert _options(config, "cloudwatch-logs").get("log_group_name") != (
        "repo-log-group"
    )


@pytest.mark.unit
def test_an_uploaded_config_is_covered(tmp_path, ash_log):
    upload = _write_config(
        tmp_path / "upload" / "ash.yaml",
        {"bedrock-summary-reporter": {"options": {"aws_region": "repo-region-1"}}},
    )
    source = tmp_path / "repo"
    source.mkdir()

    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    # Refused, naming the option, rather than resolved with it reset.
    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(config_path=upload, source_dir=source, untrusted_config=True)
    assert "aws_region" in str(refused.value)


# Walks every built-in reporter's config model in a subprocess, because loading a
# plugin package registers its plugins for the rest of the process. For each
# reporter it reports the section-level fields, every options field (each member
# of a Union, and fields of nested models as dotted paths) with its aliases, and
# whether a path in ``extension`` is refused.
_DUMP_REPORTER_FIELDS = """
import json, pkgutil, typing
from pydantic import BaseModel
from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import (
    load_additional_plugin_modules, load_internal_plugins)
import automated_security_helper.plugin_modules as pm

load_internal_plugins()
load_additional_plugin_modules(
    [pm.__name__ + "." + i.name for i in pkgutil.iter_modules(pm.__path__)])

def models(annotation):
    found, pending = [], [annotation]
    while pending:
        item = pending.pop()
        if isinstance(item, type) and issubclass(item, BaseModel):
            found.append(item)
        else:
            pending.extend(typing.get_args(item))
    return found

def walk(model, prefix, out, seen):
    if model in seen:
        return
    seen = seen | {model}
    for name, field in model.model_fields.items():
        path = prefix + name
        out.append({
            "path": path,
            "alias": field.alias,
            "validation_alias": None if field.validation_alias is None
            else str(field.validation_alias),
        })
        for nested in models(field.annotation):
            walk(nested, path + ".", out, seen)

out = {}
for cls in ash_plugin_manager.plugin_modules("reporter"):
    configs = models(cls.model_fields["config"].annotation)
    # The annotation can name a base config model beside the reporter's own; the
    # reporter is built with the most-derived one, so only its default counts.
    derived = [c for c in configs
               if not any(o is not c and issubclass(o, c) for o in configs)]
    section, options, enabled_defaults = set(), [], []
    refuses_paths = True
    for config in configs:
        section |= set(config.model_fields)
        if config in derived:
            enabled_defaults.append(
                config.model_fields["enabled"].get_default(call_default_factory=True))
        for options_model in models(config.model_fields["options"].annotation):
            walk(options_model, "", options, frozenset())
        try:
            built = config.model_validate({"extension": "x/../../escaped"})
            refuses_paths = refuses_paths and built.extension != "x/../../escaped"
        except Exception:
            pass
    declared = getattr(cls, "destination_options", None)
    out[plugin_config_key(cls)] = {
        "section": sorted(section),
        "options": options,
        "refuses_paths_in_extension": refuses_paths,
        "destination_options": None if declared is None else list(declared),
        "enabled_defaults": enabled_defaults,
    }
print(json.dumps(out))
"""

#: Section-level fields every reporter has. A new one fails the guard below until
#: it is classified. ``extension`` names the report file, so it is validated as a
#: filename suffix from every source (base/reporter_plugin.py).
_REVIEWED_SECTION_FIELDS = {"name", "enabled", "options", "extension"}

#: Options listed before the reporter's own model defines them. They are added to
#: the model on another branch, and listing them first keeps a repository's or a
#: client's config from setting them in between. When the model gains one, the
#: tests below fail until it is removed from here and added to the reporter's
#: ``destination_options``. Empty now: the Security Hub reporter's model defines
#: ``archive_resolved_findings`` and ``findings_scope`` and declares both.
_LISTED_BEFORE_DEFINED: set = set()

#: Options whose names look like a destination but are not one.
_REVIEWED_NOT_DESTINATIONS = {
    ("s3", "file_format"): "picks JSON or YAML for the object's content",
    ("gitlab-cyclonedx", "input_file_path_override"): (
        "a value written into the report's content, not a file ASH reads or writes"
    ),
}

_DESTINATION_LIKE = re.compile(
    r"(^|_)(region|profile|account|bucket|key_prefix|log_group|log_stream|"
    r"model_id|endpoint|url|uri|host|webhook|topic|queue|role|arn|credentials?|"
    r"secret|token|password|api_key|access_key|path|dir|directory|destination|"
    r"file)(_|$)"
)


@pytest.fixture(scope="module")
def reporter_fields(tmp_path_factory):
    result = subprocess.run(  # nosec B603 - fixed argv: this interpreter, literal probe
        [sys.executable, "-c", _DUMP_REPORTER_FIELDS],
        cwd=tmp_path_factory.mktemp("fields"),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.integration
def test_every_destination_like_option_of_a_built_in_reporter_is_listed(
    reporter_fields,
):
    """A reporter option added later with a destination-like name has to be listed."""
    from automated_security_helper.config.reporter_trust import (
        REPORTER_DESTINATION_OPTIONS,
    )

    unlisted = []
    for reporter, fields in reporter_fields.items():
        listed = REPORTER_DESTINATION_OPTIONS.get(reporter, ())
        for field in fields["options"]:
            leaf = field["path"].rpartition(".")[2]
            top = field["path"].partition(".")[0]
            if not _DESTINATION_LIKE.search(leaf):
                continue
            if (reporter, field["path"]) in _REVIEWED_NOT_DESTINATIONS:
                continue
            if top not in listed:
                unlisted.append((reporter, field["path"]))
    assert not unlisted
    for reporter, names in REPORTER_DESTINATION_OPTIONS.items():
        assert reporter in reporter_fields, reporter
        paths = {f["path"] for f in reporter_fields[reporter]["options"]}
        defined = {
            name for name in names if (reporter, name) not in _LISTED_BEFORE_DEFINED
        }
        assert defined <= paths, (reporter, names)
        # One the model now defines has to leave the not-yet-defined list.
        pending = {name for name in names if (reporter, name) in _LISTED_BEFORE_DEFINED}
        assert not pending & paths, (reporter, pending & paths)
    assert all(
        name in REPORTER_DESTINATION_OPTIONS.get(r, ())
        for r, name in _LISTED_BEFORE_DEFINED
    )


@pytest.mark.integration
def test_each_built_in_reporter_declares_the_options_listed_for_it(reporter_fields):
    """The table covers a reporter before its plugin package is imported, and the
    declaration after; the two must not drift apart."""
    from automated_security_helper.config.reporter_trust import (
        REPORTER_DESTINATION_OPTIONS,
    )

    declared = {
        reporter: fields["destination_options"]
        for reporter, fields in reporter_fields.items()
    }
    # An option the model does not define yet cannot be declared on the class.
    assert {
        reporter: [
            name
            for name in REPORTER_DESTINATION_OPTIONS.get(reporter, ())
            if (reporter, name) not in _LISTED_BEFORE_DEFINED
        ]
        for reporter in declared
    } == declared
    assert set(REPORTER_DESTINATION_OPTIONS) <= set(declared)


@pytest.mark.integration
def test_every_retry_option_of_an_off_host_reporter_is_listed(reporter_fields):
    """A reporter that gains retry options has to list them as the operator's."""
    unlisted = [
        (reporter, field["path"])
        for reporter in REPORTER_ENABLED_DEFAULTS
        for field in reporter_fields[reporter]["options"]
        if field["path"] in _RETRY_OPTIONS
        and field["path"] not in REPORTER_DESTINATION_OPTIONS[reporter]
    ]
    assert not unlisted
    assert {
        reporter
        for reporter in REPORTER_ENABLED_DEFAULTS
        if any(
            f["path"] in _RETRY_OPTIONS for f in reporter_fields[reporter]["options"]
        )
    } == set(_RETRYING)


@pytest.mark.integration
def test_each_off_host_reporters_enabled_default_is_listed(reporter_fields):
    """A reporter's ``enabled`` is confined against its own default, which the
    table gives before its plugin package is imported."""
    from automated_security_helper.config.reporter_trust import (
        REPORTER_DESTINATION_OPTIONS,
        REPORTER_ENABLED_DEFAULTS,
    )

    assert set(REPORTER_ENABLED_DEFAULTS) == set(REPORTER_DESTINATION_OPTIONS)
    for reporter, default in REPORTER_ENABLED_DEFAULTS.items():
        assert set(reporter_fields[reporter]["enabled_defaults"]) == {default}, reporter


@pytest.mark.integration
def test_no_listed_option_has_an_alias(reporter_fields):
    """reporter_trust matches the options by field name, as written in the config."""
    from automated_security_helper.config.reporter_trust import (
        REPORTER_DESTINATION_OPTIONS,
    )

    aliased = [
        (reporter, field["path"], field["alias"], field["validation_alias"])
        for reporter, names in REPORTER_DESTINATION_OPTIONS.items()
        for field in reporter_fields[reporter]["options"]
        if field["path"] in names
        and (field["alias"] is not None or field["validation_alias"] is not None)
    ]
    assert not aliased


_MODEL_PARAMETER = (
    "a model parameter: how the model writes the summary, not what it is sent"
)
_SUMMARY_SHAPE = (
    "the shape of the summary ASH writes locally, with no model call of its own"
)

#: Options of the off-host reporters that a repository's config may still set,
#: each with why. Every other option of their models is in
#: REPORTER_DESTINATION_OPTIONS. Under the MCP server none of them is open: every
#: off-host reporter's section is a whole-section default denied_paths entry
#: (``test_every_off_host_reporter_is_denied_to_a_client_as_a_whole_section``).
_OPEN_OFF_HOST_OPTIONS: Dict[Tuple[str, str], str] = {
    ("s3", "file_format"): (
        "picks JSON or YAML for the uploaded object's content; where it goes and "
        "what it holds are unchanged"
    ),
    ("bedrock-summary-reporter", "temperature"): _MODEL_PARAMETER,
    ("bedrock-summary-reporter", "top_p"): _MODEL_PARAMETER,
    ("bedrock-summary-reporter", "max_tokens"): _MODEL_PARAMETER,
    ("bedrock-summary-reporter", "summary_style"): (
        "read by nothing: the reporter's prompts do not use it"
    ),
    ("bedrock-summary-reporter", "add_table_of_contents"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "enable_caching"): (
        "whether ASH reuses a response it already has for the same request"
    ),
}


@pytest.mark.integration
def test_every_option_of_an_off_host_reporter_is_classified(reporter_fields):
    """A new option fails here until it is made the operator's or listed as open."""
    unclassified = [
        (reporter, field["path"])
        for reporter in REPORTER_ENABLED_DEFAULTS
        for field in reporter_fields[reporter]["options"]
        if "." not in field["path"]
        and field["path"] not in REPORTER_DESTINATION_OPTIONS[reporter]
        and (reporter, field["path"]) not in _OPEN_OFF_HOST_OPTIONS
    ]
    assert not unclassified
    stale = [
        key
        for key in _OPEN_OFF_HOST_OPTIONS
        if key[1] not in {f["path"] for f in reporter_fields[key[0]]["options"]}
        or key[1] in REPORTER_DESTINATION_OPTIONS[key[0]]
    ]
    assert not stale


@pytest.mark.unit
def test_every_off_host_reporter_is_denied_to_a_client_as_a_whole_section():
    """So a client can neither turn one on nor configure it, and an option added
    later is denied before anyone lists it. A client's ``enabled: false`` is still
    accepted under the entry (``client_config_policy._writes_a_tightening`` and
    ``runtime_patch._turns_an_off_host_reporter_off``)."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.client_config_policy import (
        SHIPPED_DEFAULT_DENIED_PATHS,
        _names,
    )

    shipped = RuntimeOverridesConfig().denied_paths
    for reporter in REPORTER_ENABLED_DEFAULTS:
        assert f"/reporters/{reporter}/**" in shipped, reporter
        assert f"/reporters/{reporter}/**" in SHIPPED_DEFAULT_DENIED_PATHS[-1]
    # enabled is denied for the off-host reporters only: a client may still turn
    # a local reporter on or off.
    assert not any(_names(e, "/reporters/sarif/enabled") for e in shipped)


@pytest.mark.integration
def test_every_section_level_field_is_reviewed(reporter_fields):
    unreviewed = {
        reporter: sorted(set(fields["section"]) - _REVIEWED_SECTION_FIELDS)
        for reporter, fields in reporter_fields.items()
        if set(fields["section"]) - _REVIEWED_SECTION_FIELDS
    }
    assert not unreviewed


@pytest.mark.integration
def test_every_reporter_refuses_a_path_in_its_extension(reporter_fields):
    accepting = sorted(
        reporter
        for reporter, fields in reporter_fields.items()
        if not fields["refuses_paths_in_extension"]
    )
    assert not accepting


@pytest.mark.integration
def test_the_field_walker_sees_unions_nested_models_and_aliases(tmp_path):
    """The dump above walks what a future options model might use."""
    probe = _DUMP_REPORTER_FIELDS.split("out = {}")[0] + (
        "from typing import Optional, Union, List\n"
        "from pydantic import Field\n"
        "class Inner(BaseModel):\n"
        "    webhook_url: str = ''\n"
        "class A(BaseModel):\n"
        "    nested: Optional[List[Inner]] = None\n"
        "class B(BaseModel):\n"
        "    target: str = Field('', alias='bucketName')\n"
        "found = []\n"
        "for m in models(Union[A, B]):\n"
        "    walk(m, '', found, frozenset())\n"
        "print(json.dumps(found))\n"
    )
    result = subprocess.run(  # nosec B603 - fixed argv: this interpreter, literal probe
        [sys.executable, "-c", probe],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    found = json.loads(result.stdout.strip().splitlines()[-1])
    paths = {f["path"]: f for f in found}
    assert "nested.webhook_url" in paths
    assert paths["target"]["alias"] == "bucketName"
