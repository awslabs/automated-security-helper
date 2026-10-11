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
from typing import Dict, List, Tuple

import pytest
import yaml

from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
    REPORTER_ENABLED_DEFAULTS,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER

#: Values that read like what a repository would write, for some options. Every
#: other option gets ``repo-<name>``, which no default is.
_EXAMPLE_VALUES: Dict[str, str] = {
    "aws_region": "repo-region-1",
    "account_id": "000000000001",
    # Plain file names: a path is replaced by the options' own validation from
    # any source, which would satisfy these tests without the destination check.
    "output_file": "repo-summary.md",
    "output_executive_file": "repo-executive.md",
    "output_technical_file": "repo-technical.md",
}

# Every option listed in config/reporter_trust.py, with a value no default has.
# Derived from the table, so an option added there is covered here.
REPO_VALUES: Dict[str, Dict[str, str]] = {
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


#: What the Bedrock reporter sends to the model besides the findings, each with a
#: value other than its default.
_BEDROCK_CONTENT = {"include_code_snippets": True, "custom_prompt": "Repo prompt."}


@pytest.mark.parametrize("name", sorted(_BEDROCK_CONTENT))
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
_RETRYING = ("bedrock-summary-reporter", "cloudwatch-logs", "s3")
_RETRY_OPTIONS = ("max_retries", "base_delay", "max_delay")
_RETRY_CASES = [(r, n) for r in _RETRYING for n in _RETRY_OPTIONS]


@pytest.mark.parametrize(
    "reporter,name", _RETRY_CASES, ids=[f"{r}.{n}" for r, n in _RETRY_CASES]
)
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
def test_a_repository_config_repeating_the_operators_value_applies(
    tmp_path, ash_log, reporter, name
):
    """The same value is no change: it applies, with no warning."""
    section = {reporter: {"options": {name: REPO_VALUES[reporter][name]}}}
    source = tmp_path / "repo"
    project = _write_config(source / ".ash" / ".ash.yaml", section)
    operator = _write_config(tmp_path / "operator" / "ash.yaml", section)

    config = resolve_config(
        config_path=project, source_dir=source, trusted_config_path=operator
    )

    assert _options(config, reporter)[name] == REPO_VALUES[reporter][name]
    assert not any(name in message for message in _warnings(ash_log))


@pytest.mark.parametrize(
    "spelling", ["BedrockSummary", "bedrocksummaryreporter", "Bedrock_Summary_Reporter"]
)
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


def test_other_reporter_options_in_the_tree_still_apply(tmp_path, ash_log):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml",
        {
            "bedrock-summary-reporter": {
                "enabled": False,
                "options": {
                    "max_findings_to_analyze": 3,
                    "aws_region": "repo-region-1",
                },
            },
            "s3": {"options": {"file_format": "yaml"}},
            "markdown": {"options": {"compact": True}},
        },
    )

    config = resolve_config(source_dir=source)

    bedrock = config.get_plugin_config("reporter", "bedrock-summary-reporter")
    assert bedrock["enabled"] is False
    assert bedrock["options"]["max_findings_to_analyze"] == 3
    assert _options(config, "s3")["file_format"] == "yaml"
    assert config.reporters.markdown.options.compact is True


def test_no_warning_when_the_tree_sets_no_destination(tmp_path, ash_log):
    source = tmp_path / "repo"
    _write_config(
        source / ".ash" / ".ash.yaml", {"s3": {"options": {"file_format": "yaml"}}}
    )

    resolve_config(source_dir=source)

    assert not any("reporters." in message for message in _warnings(ash_log))


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


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
def test_an_in_tree_config_may_turn_one_off(tmp_path, ash_log, reporter):
    """``enabled: false`` only narrows what is sent, so it applies from any config."""
    source = tmp_path / "repo"
    _write_config(source / ".ash" / ".ash.yaml", {reporter: {"enabled": False}})

    config = resolve_config(source_dir=source)

    assert _enabled(config, reporter) is False
    assert not any("enabled" in message for message in _warnings(ash_log))


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
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

    Stands in for a release whose reporter models default ``enabled`` to false.
    ``test_each_off_host_reporters_enabled_default_is_listed`` holds the table
    equal to the models, so such a release changes both.
    """
    for reporter in REPORTER_ENABLED_DEFAULTS:
        monkeypatch.setitem(REPORTER_ENABLED_DEFAULTS, reporter, False)


@pytest.mark.parametrize("reporter", sorted(REPORTER_ENABLED_DEFAULTS))
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
def test_off_by_default_a_delivered_config_cannot_enable_it(
    tmp_path, ash_log, defaults_off, reporter
):
    """Refused under the default denied_paths, and kept off under a policy that
    does not deny the field: the confinement holds on its own."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.client_config_policy import rules_from
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    upload = _write_config(
        tmp_path / "upload" / "ash.yaml", {reporter: {"enabled": True}}
    )
    source = tmp_path / "repo"
    source.mkdir()

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        resolve_config(config_path=upload, source_dir=source, untrusted_config=True)
    assert f"reporters.{reporter}.enabled" in str(refused.value)

    narrow = rules_from(
        AshConfig.model_validate(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "denied_paths": ["/fail_on_findings"],
                            "replace_default_denied_paths": True,
                        }
                    }
                }
            }
        )
    )
    config = resolve_config(
        config_path=upload,
        source_dir=source,
        untrusted_config=True,
        client_config_policy=narrow,
    )
    assert _enabled(config, reporter) is False


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


def test_the_example_values_cover_the_table():
    """An option added to the table gets a value above without another edit."""
    assert {r: set(v) for r, v in REPO_VALUES.items()} == {
        r: set(names) for r, names in REPORTER_DESTINATION_OPTIONS.items()
    }


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


def test_a_config_inside_the_checkout_but_outside_the_source_dir(tmp_path, ash_log):
    """CLI scan of a directory in a checkout: the tree is the whole checkout."""
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
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
    section, options, enabled_defaults = set(), [], []
    refuses_paths = True
    for config in configs:
        section |= set(config.model_fields)
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
#: ``destination_options``.
_LISTED_BEFORE_DEFINED = {
    ("aws-security-hub", "archive_resolved_findings"),
    ("aws-security-hub", "findings_scope"),
}

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
    result = subprocess.run(
        [sys.executable, "-c", _DUMP_REPORTER_FIELDS],
        cwd=tmp_path_factory.mktemp("fields"),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


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
    "the shape of the summary ASH writes locally, or which sections it asks for"
)
_FINDINGS_SENT = (
    "chooses which findings, or how many, are sent to the model with them; still "
    "set from the tree, as only include_code_snippets and custom_prompt of this "
    "kind are the operator's"
)
_CONTEXT_SENT = (
    "text added to every prompt, as custom_prompt is; still set from the tree, as "
    "only include_code_snippets and custom_prompt of this kind are the operator's"
)

#: Options of the off-host reporters that a repository's config may still set,
#: each with why. Every other option of their models is in
#: REPORTER_DESTINATION_OPTIONS. Under the MCP server a delivered config may set
#: one only where no default denied_paths entry covers it
#: (``test_the_coverage_table_is_what_the_default_list_gives``).
_OPEN_OFF_HOST_OPTIONS: Dict[Tuple[str, str], str] = {
    ("s3", "file_format"): (
        "picks JSON or YAML for the uploaded object's content; where it goes and "
        "what it holds are unchanged"
    ),
    ("bedrock-summary-reporter", "temperature"): _MODEL_PARAMETER,
    ("bedrock-summary-reporter", "top_p"): _MODEL_PARAMETER,
    ("bedrock-summary-reporter", "max_tokens"): _MODEL_PARAMETER,
    ("bedrock-summary-reporter", "summary_style"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "group_by_severity"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "add_section_headers"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "add_table_of_contents"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "output_markdown"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "include_sections"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "exclude_sections"): _SUMMARY_SHAPE,
    ("bedrock-summary-reporter", "enable_caching"): (
        "whether ASH reuses a response it already has for the same request"
    ),
    ("bedrock-summary-reporter", "enable_fallback_models"): (
        "whether ASH tries another model of the same family from its own list "
        "when model_id is unavailable; still set from the tree"
    ),
    ("bedrock-summary-reporter", "max_findings_to_analyze"): _FINDINGS_SENT,
    ("bedrock-summary-reporter", "max_findings_per_severity"): _FINDINGS_SENT,
    ("bedrock-summary-reporter", "actionable_only"): _FINDINGS_SENT,
    ("bedrock-summary-reporter", "exclude_scanner_types"): _FINDINGS_SENT,
    ("bedrock-summary-reporter", "summarize_findings"): _FINDINGS_SENT,
    ("bedrock-summary-reporter", "batch_processing"): _FINDINGS_SENT,
    ("bedrock-summary-reporter", "industry_context"): _CONTEXT_SENT,
    ("bedrock-summary-reporter", "compliance_frameworks"): _CONTEXT_SENT,
    ("bedrock-summary-reporter", "custom_context"): _CONTEXT_SENT,
}

#: How each off-host reporter's settings stand under the MCP server's default
#: denied_paths: "section" when every setting of the section is denied (with
#: ``enabled: false`` still accepted), else "options" when each operator-only
#: option and ``enabled`` are denied one by one.
_MCP_COVERAGE: Dict[str, str] = {
    "aws-security-hub": "section",
    "bedrock-summary-reporter": "section",
    "cloudwatch-logs": "section",
    "s3": "options",
}


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


def test_a_reporter_with_nothing_open_is_denied_as_a_whole_section():
    """So an option added later is denied to a client before anyone lists it."""
    with_open = {reporter for reporter, _ in _OPEN_OFF_HOST_OPTIONS}
    for reporter in REPORTER_ENABLED_DEFAULTS:
        if reporter not in with_open:
            assert _MCP_COVERAGE[reporter] == "section", reporter


def test_the_coverage_table_is_what_the_default_list_gives():
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.client_config_policy import _names

    shipped = RuntimeOverridesConfig().denied_paths
    for reporter, mode in _MCP_COVERAGE.items():
        whole = f"/reporters/{reporter}/**" in shipped
        assert whole is (mode == "section"), reporter
        if mode == "options":
            assert f"/reporters/{reporter}/enabled" in shipped, reporter
            for open_reporter, name in _OPEN_OFF_HOST_OPTIONS:
                if open_reporter == reporter:
                    pointer = f"/reporters/{reporter}/options/{name}"
                    assert not any(_names(e, pointer) for e in shipped), pointer
    # enabled is denied for the off-host reporters only: a client may still turn
    # a local reporter on or off.
    assert not any(_names(e, "/reporters/sarif/enabled") for e in shipped)


def test_every_section_level_field_is_reviewed(reporter_fields):
    unreviewed = {
        reporter: sorted(set(fields["section"]) - _REVIEWED_SECTION_FIELDS)
        for reporter, fields in reporter_fields.items()
        if set(fields["section"]) - _REVIEWED_SECTION_FIELDS
    }
    assert not unreviewed


def test_every_reporter_refuses_a_path_in_its_extension(reporter_fields):
    accepting = sorted(
        reporter
        for reporter, fields in reporter_fields.items()
        if not fields["refuses_paths_in_extension"]
    )
    assert not accepting


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
    result = subprocess.run(
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
