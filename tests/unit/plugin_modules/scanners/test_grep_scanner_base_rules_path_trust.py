# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One resolver for the configured rules in both modes, and what the staleness
bookkeeping says about a scan that read no cache.

- ``options.config`` naming a local rule file goes through
  ``config/path_trust.honored_path`` online as well as offline: a relative value
  is taken from the source directory in both modes, the two modes hand the tool
  the same absolute path, and a path inside the scanned tree is refused in both.
  Online used to pass the value as written, so ``config: my-rules.yaml`` could run
  one file online and another offline, and a file the scanned repository shipped
  ran online.
- A refused or unresolvable configured value online falls back to the default
  rulesets with a warning, never to the raw value.
- ``content_databases_in_use`` names the offline ruleset only when the scan read
  the cache: patterns mode, the operator's local rules and a missing cache read
  none, so the result is not graded on the cache's age. The staleness probe is
  pointed at the cache absolutely, as the command was.

Building the scanners probes uv and opengrep; the unit conftest's tool guard answers
the probes as a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
    SemgrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


SCANNERS = [
    pytest.param(
        SemgrepScanner,
        SemgrepScannerConfig,
        SemgrepScannerConfigOptions,
        "SEMGREP_RULES_CACHE_DIR",
        id="semgrep",
    ),
    pytest.param(
        OpengrepScanner,
        OpengrepScannerConfig,
        OpengrepScannerConfigOptions,
        "OPENGREP_RULES_CACHE_DIR",
        id="opengrep",
    ),
]

RULE = "rules:\n  - id: placeholder\n    languages: [python]\n    message: m\n    severity: INFO\n    pattern: $X == $X\n"


def _configs(scanner) -> list[str]:
    return [arg.value for arg in scanner.args.extra_args if arg.key == "--config"]


def _online(monkeypatch, scanner_cls):
    monkeypatch.setattr(scanner_cls, "_scanner_offline", lambda self: False)


def _rules_beside_the_tree(test_plugin_context) -> Path:
    source_dir = Path(test_plugin_context.source_dir)
    rules_dir = source_dir.parent / "rules-beside-the-tree"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rules = rules_dir / "my-rules.yaml"
    rules.write_text(RULE, encoding="utf-8")
    return rules


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_online_takes_a_relative_config_from_the_source_directory(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """Fails at the base: online passed ``../rules-beside-the-tree/my-rules.yaml``
    as written, for the tool to resolve wherever it ran."""
    rules = _rules_beside_the_tree(test_plugin_context)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(
            options=options_cls(
                offline=False, config="../rules-beside-the-tree/my-rules.yaml"
            )
        ),
    )

    assert _configs(scanner) == [Path(os.path.realpath(rules)).as_posix()]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_both_modes_hand_the_tool_the_same_rule_file(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """One resolver: the same configuration names one file online and offline.

    Fails at the base: offline resolved the value against ASH's working directory
    and online passed it as written, two different answers for one value.
    """
    rules = _rules_beside_the_tree(test_plugin_context)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(cache_env, raising=False)
    relative = "../rules-beside-the-tree/my-rules.yaml"

    offline = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True, config=relative)),
    )
    _online(monkeypatch, scanner_cls)
    online = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False, config=relative)),
    )

    assert _configs(offline) == _configs(online)
    assert _configs(online) == [Path(os.path.realpath(rules)).as_posix()]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_online_refuses_a_rule_file_inside_the_scanned_tree(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    monkeypatch,
    caplog,
):
    """Fails at the base: a rules file the scanned repository shipped was passed
    online as written. It is refused with a warning and the default rulesets run."""
    source_dir = Path(test_plugin_context.source_dir)
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "shipped-rules.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    with caplog.at_level("WARNING"):
        scanner = scanner_cls(
            context=test_plugin_context,
            config=config_cls(
                options=options_cls(offline=False, config="shipped-rules.yaml")
            ),
        )

    configs = _configs(scanner)
    assert not any("shipped-rules" in value for value in configs), configs
    assert configs == list(scanner.default_rulesets()), configs
    assert any("options.config" in record.getMessage() for record in caplog.records), [
        record.getMessage() for record in caplog.records
    ]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_online_passes_a_registry_name_as_written(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """The control: a registry entry is no path and reaches the tool untouched."""
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False, config="p/security")),
    )

    assert _configs(scanner) == ["p/security"]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_local_rules_offline_declare_no_content_database(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """Fails at the base: offline declared the ruleset whenever the mode was
    offline, so a scan that ran the operator's own rules was graded on the age of
    a cache it never read."""
    rules = _rules_beside_the_tree(test_plugin_context)
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "registry.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv(cache_env, str(cache))

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True, config=str(rules))),
    )

    assert cache.as_posix() not in _configs(scanner)
    assert scanner.content_databases_in_use() == []


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_missing_cache_offline_declares_no_content_database(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """Fails at the base: with no cache the scanner declined, and still declared
    the ruleset, so the probe was pointed at a cache_dir of None."""
    monkeypatch.delenv(cache_env, raising=False)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True)),
    )

    assert scanner.dependency_unavailable_reason is not None
    assert scanner.content_databases_in_use() == []


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_the_cache_the_command_read_is_declared_and_probed_absolutely(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """The control, and the probe's path: a scan that read the cache declares the
    ruleset, and the probe is pointed at the cache as the command named it, not at
    the relative spelling of the environment variable.

    Fails at the base for the probe path: the raw environment value was passed.
    """
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "ci.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(cache_env, "rules")

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True)),
    )

    expected = os.path.abspath("rules")
    assert expected in _configs(scanner), _configs(scanner)
    declared = ScannerPluginBase.content_databases_in_use(scanner)
    assert declared, "premise: the offline ruleset is a declared content database"
    assert scanner.content_databases_in_use() == declared
    context = scanner.content_database_probe_context()
    assert context.cache_dir == expected
    assert os.path.isabs(context.cache_dir)


def test_opengrep_patterns_mode_offline_declares_no_content_database(
    test_plugin_context, tmp_path, monkeypatch
):
    """Fails at the base: patterns mode reads no rules at all, and the ruleset was
    still declared for it."""
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "registry.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv("OPENGREP_RULES_CACHE_DIR", str(cache))

    scanner = OpengrepScanner(
        context=test_plugin_context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=True, patterns=["$X == $X"])
        ),
    )

    assert cache.as_posix() not in _configs(scanner)
    assert scanner.content_databases_in_use() == []
