# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which rules an offline grep-family scan runs, and how they are named to the tool.

- An operator's ``options.config`` that names a local rule file or directory is what
  the scan runs with offline, as it is online. It used to be dropped: offline mode
  read only the cache directory, and a local YAML that needs no network was replaced
  by the cached registry rules without a word.
- The cache directory and a local config reach the tool as absolute paths. The
  directory is validated against ASH's working directory and the tool runs in the
  source directory, so a relative value named a different directory there. A local
  config is taken from the source directory, as every tool path option is
  (``config/path_trust``); the path-trust judgment itself is covered in
  ``test_grep_scanner_base_registry_names.py`` and
  ``test_grep_scanner_base_rules_path_trust.py``.
- ``--no-rewrite-rule-ids`` is passed online as well as offline, so ASH's bundled
  rules keep one id whatever mode the scan ran in.

Building the scanners probes uv and opengrep; the unit conftest's tool guard answers
the probes as a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

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


def _pairs(scanner) -> list[tuple[str, str]]:
    return [(arg.key, arg.value) for arg in scanner.args.extra_args]


def _configs(scanner) -> list[str]:
    return [value for key, value in _pairs(scanner) if key == "--config"]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_offline_runs_the_configured_local_rule_file(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """A local rule file in ``options.config`` is the offline scan's rules, and
    no cache directory is needed for it.

    Fails at the base: with no cache the scanner recorded the missing-cache reason
    and declined, the configured file never reaching the command.
    """
    rules = tmp_path / "my-rules.yaml"
    rules.write_text(RULE, encoding="utf-8")
    monkeypatch.delenv(cache_env, raising=False)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True, config=str(rules))),
    )

    assert scanner.dependency_unavailable_reason is None
    assert rules.as_posix() in _configs(scanner), _pairs(scanner)
    assert not any(
        value in _configs(scanner) for value in scanner.default_rulesets()
    ), _pairs(scanner)


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_offline_runs_the_configured_local_rule_directory_over_the_cache(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """With both a cache and a configured local directory, the configured one
    runs, as online passes the configured rules alone.

    Fails at the base: the cache directory was the only ``--config`` offline.
    """
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "registry.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv(cache_env, str(cache))
    own = tmp_path / "own-rules"
    own.mkdir()
    (own / "a.yml").write_text(RULE, encoding="utf-8")

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True, config=str(own))),
    )

    configs = _configs(scanner)
    assert scanner.dependency_unavailable_reason is None
    assert own.as_posix() in configs, configs
    assert Path(os.path.realpath(cache)).as_posix() not in configs, configs


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_relative_local_config_reaches_the_tool_as_an_absolute_path(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    tmp_path,
    monkeypatch,
):
    """A relative path is taken from the source directory, as every tool path
    option is (``path_trust.resolved_path``), and reaches the tool absolute. A
    directory beside the scanned one, outside every checkout, is a path the
    scanner may pass. ASH's working directory plays no part: it is moved two
    levels down, where the same relative value names a DECOY file, so a
    resolution from the working directory produces a different path than one from
    the source directory, and the test tells them apart."""
    source_dir = Path(context_outside_checkouts.source_dir)
    rules_dir = source_dir.parent / "rules-beside-the-tree"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "my-rules.yaml").write_text(RULE, encoding="utf-8")
    elsewhere = tmp_path / "deep" / "elsewhere"
    elsewhere.mkdir(parents=True)
    decoy = tmp_path / "deep" / "rules-beside-the-tree" / "my-rules.yaml"
    decoy.parent.mkdir(parents=True)
    decoy.write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv(cache_env, raising=False)

    scanner = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(
            options=options_cls(
                offline=True, config="../rules-beside-the-tree/my-rules.yaml"
            )
        ),
    )

    configs = [Path(value) for value in _configs(scanner)]
    assert Path(os.path.realpath(rules_dir / "my-rules.yaml")) in configs, configs
    assert Path(os.path.realpath(decoy)) not in configs, configs
    assert all(path.is_absolute() for path in configs), configs


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_registry_name_offline_still_needs_the_cache(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """The control: ``p/ci`` is no local path, so offline without a cache the
    scanner records the reason and declines, as before."""
    monkeypatch.delenv(cache_env, raising=False)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True, config="p/ci")),
    )

    assert cache_env in (scanner.dependency_unavailable_reason or "")
    assert scanner.validate_plugin_dependencies() is False


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_relative_cache_directory_reaches_the_tool_as_an_absolute_path(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """The cache directory is validated against ASH's working directory; the
    tool, run in the source directory, gets the directory that was validated.

    Fails at the base: the environment value was passed as written.
    """
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "ci.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(cache_env, "rules")

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True)),
    )

    assert scanner.dependency_unavailable_reason is None
    configs = _configs(scanner)
    assert "rules" not in configs, configs
    assert Path(os.getcwd()) / "rules" in [Path(value) for value in configs], configs


def test_semgrep_rules_environment_names_the_cache_absolutely(
    test_plugin_context, tmp_path, monkeypatch
):
    """``SEMGREP_RULES``, which semgrep reads in the source directory, names the
    validated cache directory, not the relative spelling."""
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "ci.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SEMGREP_RULES_CACHE_DIR", "rules")

    scanner = SemgrepScanner(
        context=test_plugin_context,
        config=SemgrepScannerConfig(options=SemgrepScannerConfigOptions(offline=True)),
    )

    env = scanner.extra_subprocess_env() or {}
    assert env.get("SEMGREP_RULES") == f"{os.path.join(os.getcwd(), 'rules')}/*"


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_rule_ids_are_not_rewritten_online(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """``--no-rewrite-rule-ids`` online too, so a bundled rule has the same id in
    both modes.

    Fails at the base: the flag was appended by the offline branch only.
    """
    monkeypatch.delenv(cache_env, raising=False)
    monkeypatch.setattr(scanner_cls, "_scanner_offline", lambda self: False)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False)),
    )

    keys = [key for key, _ in _pairs(scanner)]
    assert keys.count("--no-rewrite-rule-ids") == 1, keys


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_rule_ids_are_not_rewritten_offline(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """The control: offline keeps the flag, once."""
    (tmp_path / "ci.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv(cache_env, str(tmp_path))

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True)),
    )

    keys = [key for key, _ in _pairs(scanner)]
    assert keys.count("--no-rewrite-rule-ids") == 1, keys


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_cache_directory_inside_the_scanned_tree_is_refused(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """A rule cache the environment names inside the scanned tree is not handed to
    the tool: the one rule every tool path follows (``config/path_trust``), so the
    scanned repository cannot choose the rules it is scanned with. The scanner
    records the reason and declines, as it does for a missing cache.

    Fails at the base: the directory passed the validator and was appended as
    ``--config`` with no judgment of where it sits.
    """
    source = Path(test_plugin_context.source_dir)
    cache = source / "rules"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "ci.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv(cache_env, str(cache))

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True)),
    )

    reason = scanner.dependency_unavailable_reason or ""
    assert cache_env in reason and "scanned tree" in reason, reason
    assert Path(os.path.realpath(cache)).as_posix() not in _configs(scanner), _pairs(
        scanner
    )
    assert scanner._cache_dir_in_use is None
    assert scanner.validate_plugin_dependencies() is False
    assert scanner.content_databases_in_use() == []
