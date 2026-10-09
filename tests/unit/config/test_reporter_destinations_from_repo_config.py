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

import logging
from pathlib import Path
from typing import Dict, List

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER

# Every option listed in config/reporter_trust.py, with a value no default has.
REPO_VALUES: Dict[str, Dict[str, str]] = {
    "aws-security-hub": {
        "aws_region": "repo-region-1",
        "aws_profile": "repo-profile",
        "account_id": "000000000001",
    },
    "bedrock-summary-reporter": {
        "aws_region": "repo-region-1",
        "aws_profile": "repo-profile",
        "model_id": "repo.standin-model",
        "output_file": "/elsewhere/summary.md",
        "output_executive_file": "../executive.md",
        "output_technical_file": "../../technical.md",
    },
    "cloudwatch-logs": {
        "aws_region": "repo-region-1",
        "log_group_name": "repo-log-group",
        "log_stream_name": "repo-log-stream",
    },
    "s3": {
        "aws_region": "repo-region-1",
        "aws_profile": "repo-profile",
        "bucket_name": "repo-bucket",
        "key_prefix": "repo-prefix/",
    },
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

    config = resolve_config(
        config_path=upload, source_dir=source, untrusted_config=True
    )

    assert _options(config, "bedrock-summary-reporter").get("aws_region") != (
        "repo-region-1"
    )


def test_every_destination_like_option_of_a_built_in_reporter_is_listed(tmp_path):
    """A reporter option added later with a destination-like name has to be listed.

    The reporters are loaded in a subprocess, because loading a plugin package
    registers its plugins for the rest of the process.
    """
    import json
    import re
    import subprocess
    import sys

    from automated_security_helper.config.reporter_trust import (
        REPORTER_DESTINATION_OPTIONS,
    )

    code = (
        "import json, pkgutil, typing\n"
        "from automated_security_helper.base.plugin_config import plugin_config_key\n"
        "from automated_security_helper.plugins import ash_plugin_manager\n"
        "from automated_security_helper.plugins.loader import (\n"
        "    load_additional_plugin_modules, load_internal_plugins)\n"
        "import automated_security_helper.plugin_modules as pm\n"
        "load_internal_plugins()\n"
        "load_additional_plugin_modules(\n"
        "    [pm.__name__ + '.' + i.name for i in pkgutil.iter_modules(pm.__path__)])\n"
        "def first(annotation):\n"
        "    args = [a for a in typing.get_args(annotation) if a is not type(None)]\n"
        "    return (args or [annotation])[0]\n"
        "out = {}\n"
        "for cls in ash_plugin_manager.plugin_modules('reporter'):\n"
        "    config = first(cls.model_fields['config'].annotation)\n"
        "    options = first(config.model_fields['options'].annotation)\n"
        "    out[plugin_config_key(cls)] = sorted(getattr(options, 'model_fields', {}))\n"
        "print(json.dumps(out))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    fields = json.loads(result.stdout.strip().splitlines()[-1])
    destination_like = re.compile(
        r"(^|_)(region|profile|account|bucket|key_prefix|log_group|log_stream|"
        r"model_id|endpoint|url|topic|queue|role|arn|credentials?|secret|token)"
        r"(_|$)|^output_\w*file$"
    )
    for reporter, names in fields.items():
        for name in names:
            if destination_like.search(name):
                assert name in REPORTER_DESTINATION_OPTIONS.get(reporter, ()), (
                    reporter,
                    name,
                )
    for reporter, names in REPORTER_DESTINATION_OPTIONS.items():
        assert reporter in fields, reporter
        assert set(names) <= set(fields[reporter]), (reporter, names)
