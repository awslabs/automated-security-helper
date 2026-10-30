# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One resolver for the configured rules in both modes, a refusal in both modes for
rules ASH cannot pass, and what the staleness bookkeeping says about a scan that
read no cache.

- ``options.config`` naming a local rule file goes through
  ``config/path_trust.honored_path`` online as well as offline: a relative value
  is taken from the source directory in both modes, the two modes hand the tool
  the same absolute path, and a path inside the scanned tree is refused in both.
  Online used to pass the value as written, so ``config: my-rules.yaml`` could run
  one file online and another offline, and a file the scanned repository shipped
  ran online.
- A configured value that is not a registry entry and resolves to nothing ASH may
  pass (a typo, a missing file, an in-tree file) DECLINES the scanner in both
  modes, with a reason naming the option; the scan never runs under the default
  rulesets or the offline cache in its place. Online used to fall back to the
  default rulesets, offline to the cache: a different scan reported as the one
  that was asked for.
- ``content_databases_in_use`` names the offline ruleset only when the scan read
  the cache: the operator's local rules and a missing cache read none, so the
  result is not graded on the cache's age. The staleness probe is pointed at the
  cache absolutely, as the command was.

The tests that expect a rules path to be PASSED build their tree with
``context_outside_checkouts`` (this directory's conftest): ``test_plugin_context``
sits under ``tests/pytest-temp`` inside the repository's checkout, where every
rules file beside it is refused by path trust. The tests that expect a REFUSAL
use ``test_plugin_context``, whose source directory is a tree like any other.

The ``--config`` values read here (``_configs``) leave out the rules ASH bundles
under its own assets directory, which ``_process_config_options`` passes on every
command in both modes: they are the same for every scanner built here and are not
what these tests judge; the operator's configured value is.

Building the scanners probes uv and opengrep; the unit conftest's tool guard answers
the probes as a host without the tools would, so nothing starts here.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.constants import ASH_ASSETS_DIR
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
    """The ``--config`` values of the command, without the rules ASH bundles.

    ``_process_config_options`` passes every rules file under the assets directory
    on every command; those are constant and not under test here.
    """
    bundled = ASH_ASSETS_DIR.joinpath("ash_stargrep_rules").as_posix()
    return [
        arg.value
        for arg in scanner.args.extra_args
        if arg.key == "--config" and not str(arg.value).startswith(bundled)
    ]


def _online(monkeypatch, scanner_cls):
    monkeypatch.setattr(scanner_cls, "_scanner_offline", lambda self: False)


def _rules_beside_the_tree(context) -> Path:
    source_dir = Path(context.source_dir)
    rules_dir = source_dir.parent / "rules-beside-the-tree"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rules = rules_dir / "my-rules.yaml"
    rules.write_text(RULE, encoding="utf-8")
    return rules


def _declined_for_its_config(scanner, name: str) -> None:
    reason = scanner.dependency_unavailable_reason or ""
    assert f"scanners.{name}.options.config" in reason, reason
    assert scanner.validate_plugin_dependencies() is False
    configs = _configs(scanner)
    assert not any(value in configs for value in scanner.default_rulesets()), configs


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_online_takes_a_relative_config_from_the_source_directory(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    tmp_path,
    monkeypatch,
):
    """Fails at the base: online passed ``../rules-beside-the-tree/my-rules.yaml``
    as written, for the tool to resolve wherever it ran."""
    rules = _rules_beside_the_tree(context_outside_checkouts)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(
            options=options_cls(
                offline=False, config="../rules-beside-the-tree/my-rules.yaml"
            )
        ),
    )

    assert scanner.dependency_unavailable_reason is None
    assert _configs(scanner) == [Path(os.path.realpath(rules)).as_posix()]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_both_modes_hand_the_tool_the_same_rule_file(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    tmp_path,
    monkeypatch,
):
    """One resolver: the same configuration names one file online and offline.

    Fails at the base: offline resolved the value against ASH's working directory
    and online passed it as written, two different answers for one value.
    """
    rules = _rules_beside_the_tree(context_outside_checkouts)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.delenv(cache_env, raising=False)
    relative = "../rules-beside-the-tree/my-rules.yaml"

    offline = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(options=options_cls(offline=True, config=relative)),
    )
    _online(monkeypatch, scanner_cls)
    online = scanner_cls(
        context=context_outside_checkouts,
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
    online as written. It is refused with a warning, and the scanner declines
    rather than running the default rulesets in its place."""
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
    _declined_for_its_config(scanner, scanner.config.name)
    assert any("options.config" in record.getMessage() for record in caplog.records), [
        record.getMessage() for record in caplog.records
    ]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_an_in_tree_rules_value_that_resolves_to_nothing_is_refused_online(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """A typo in ``options.config`` fails loudly: the scanner declines with a
    reason naming the option, instead of scanning under the default rulesets.

    What this exercises: a relative value resolves under the source directory,
    which is the scanned tree, and path trust refuses that before anything asks
    whether the file exists (the file's docstring and
    ``test_the_decline_reason_names_a_path_trust_refusal_as_such``). The
    missing-file branch is reached from a trusted location, in the two
    ``..._names_the_resolved_path_of_a_missing_rules_file...`` tests.

    Fails at the base: the value was passed as written and the tool failed on it
    at scan time, with nothing recorded at build time.
    """
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False, config="my-rulez.yaml")),
    )

    _declined_for_its_config(scanner, scanner.config.name)
    assert not any("my-rulez" in value for value in _configs(scanner)), _configs(
        scanner
    )


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_an_in_tree_rules_value_that_resolves_to_nothing_is_refused_offline_and_reads_no_cache(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    tmp_path,
    monkeypatch,
):
    """Offline, the same in-tree typo declines the scanner with the same reason
    (a path-trust refusal, as online), and the cache is NOT read in its place even
    when one is present.

    Fails at the base: a configured value that resolved to nothing fell through to
    the cache, so the scan ran the cached registry rules in place of the file the
    operator named.
    """
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "registry.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv(cache_env, str(cache))

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=True, config="my-rulez.yaml")),
    )

    _declined_for_its_config(scanner, scanner.config.name)
    assert not any("cache" in value for value in _configs(scanner)), _configs(scanner)
    assert cache_env not in (scanner.dependency_unavailable_reason or "")


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_the_decline_reason_names_the_resolved_path_of_a_missing_rules_file(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    monkeypatch,
):
    """A typo's reason shows the absolute path ASH looked for and says it does not
    exist, and names the operator sources that admit a rules file; a reader can
    tell it from a path-trust refusal.

    The missing file is named beside the scanned tree, not inside it: a relative
    value resolves under the source directory, which is the scanned tree, and path
    trust refuses that before anything asks whether the file exists, so an in-tree
    typo reads as a path-trust refusal (the test below), not as a missing file.

    Fails at the tip whose reason was one sentence listing every possible cause.
    """
    _rules_beside_the_tree(context_outside_checkouts)
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(
            options=options_cls(
                offline=False, config="../rules-beside-the-tree/my-rulez.yaml"
            )
        ),
    )

    reason = scanner.dependency_unavailable_reason or ""
    # The reason spells the path POSIX on every platform (``as_posix()``), so the
    # expected path is spelled the same way; ``os.path.realpath`` alone spells
    # backslashes on Windows and would not be found in the text there.
    expected = Path(
        os.path.realpath(
            Path(context_outside_checkouts.source_dir).parent
            / "rules-beside-the-tree"
            / "my-rulez.yaml"
        )
    ).as_posix()
    assert expected in reason, reason
    assert "does not exist" in reason, reason
    assert "path trust refused" not in reason, reason
    assert "--config-overrides" in reason, reason


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_the_decline_reason_names_the_resolved_path_of_a_missing_rules_file_offline(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    tmp_path,
    monkeypatch,
):
    """The missing-file branch offline, from a trusted location with a cache
    present: the scanner declines for the file that does not exist, and the cache
    is NOT read in its place. The in-tree offline test above cannot reach this
    branch: path trust refuses its value first.

    Fails at the base: a configured value that resolved to nothing fell through to
    the cache.
    """
    _rules_beside_the_tree(context_outside_checkouts)
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "registry.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv(cache_env, str(cache))

    scanner = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(
            options=options_cls(
                offline=True, config="../rules-beside-the-tree/my-rulez.yaml"
            )
        ),
    )

    _declined_for_its_config(scanner, scanner.config.name)
    reason = scanner.dependency_unavailable_reason or ""
    assert "does not exist" in reason, reason
    assert "path trust refused" not in reason, reason
    assert not any("cache" in value for value in _configs(scanner)), _configs(scanner)
    assert cache_env not in reason, reason


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_the_decline_reason_names_a_path_trust_refusal_as_such(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """An in-tree rules file's reason says path trust refused it, with the resolved
    path, and does not claim the file is missing."""
    source_dir = Path(test_plugin_context.source_dir)
    source_dir.mkdir(parents=True, exist_ok=True)
    (source_dir / "shipped-rules.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(
            options=options_cls(offline=False, config="shipped-rules.yaml")
        ),
    )

    reason = scanner.dependency_unavailable_reason or ""
    assert "path trust refused" in reason, reason
    # POSIX-spelled, as the reason spells it on every platform.
    expected = Path(os.path.realpath(source_dir / "shipped-rules.yaml")).as_posix()
    assert expected in reason, reason
    assert "does not exist" not in reason, reason


def _separate_checkout_with_rules(context, git: bool = True) -> Path:
    """A rules directory in a directory of its own, beside the scanned tree
    (``context.source_dir``'s parent, which ``context_outside_checkouts`` keeps
    outside every checkout), so that only the ``.git`` built here can make path
    trust read it as a checkout.

    With ``git`` the directory is a checkout: the ``.git`` holds a ``HEAD``, since
    path trust counts a directory as a checkout by the shape git's own discovery
    opens (``sandbox_grants._git_shaped``), and a bare empty ``.git`` directory,
    what a stray mkdir leaves, marks none. Without it the same layout is a plain
    directory, the control.
    """
    other = Path(context.source_dir).parent / "other-checkout"
    other.mkdir(parents=True, exist_ok=True)
    if git:
        (other / ".git").mkdir()
        (other / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    rules = other / "rules"
    rules.mkdir()
    (rules / "a.yaml").write_text(RULE, encoding="utf-8")
    return rules


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_rules_directory_in_another_checkout_is_refused_from_a_repository_config(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    monkeypatch,
):
    """A rules directory inside ANY git checkout is refused when the value is not
    the operator's own (the config that names it is read as the scanned
    repository's): ``config/path_trust.honored_path`` judges such a value with
    ``scanned_tree_reason`` (``sandbox_grants.untrusted_reason``: inside any git
    checkout). The scanner declines and the reason names the operator sources.

    The checkout is built beside the scanned tree, outside every other checkout,
    so the ``.git/HEAD`` is what causes the refusal; the control below is the same
    layout without it.
    """
    rules = _separate_checkout_with_rules(context_outside_checkouts)
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(options=options_cls(offline=False, config=str(rules))),
    )

    _declined_for_its_config(scanner, scanner.config.name)
    assert not any("other-checkout" in value for value in _configs(scanner)), _configs(
        scanner
    )
    assert "--config-overrides" in (scanner.dependency_unavailable_reason or "")


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_the_same_directory_without_a_checkout_is_admitted_from_a_repository_config(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    monkeypatch,
):
    """The control for the test above: the same layout with no ``.git`` is a plain
    directory beside the scanned tree, which a repository config may name."""
    rules = _separate_checkout_with_rules(context_outside_checkouts, git=False)
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(options=options_cls(offline=False, config=str(rules))),
    )

    assert scanner.dependency_unavailable_reason is None
    assert _configs(scanner) == [Path(os.path.realpath(rules)).as_posix()]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_rules_directory_in_another_checkout_is_admitted_from_an_operator_source(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    tmp_path,
    monkeypatch,
):
    """The same directory named by the operator (here through a
    ``--config-overrides`` entry recorded in ``AshConfig._operator_paths``) is
    admitted: an operator's value is judged by ``operator_reason``
    (``sandbox_grants.in_tree_reason``: the scanned tree itself, never another
    checkout), so a rules repository checked out elsewhere is the operator's to
    name. Only the scanned tree stays refused for the operator too."""
    from automated_security_helper.config.path_trust import OperatorPaths

    rules = _separate_checkout_with_rules(context_outside_checkouts)
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)
    config = config_cls(options=options_cls(offline=False, config=str(rules)))
    context_outside_checkouts.config._operator_paths = OperatorPaths(
        overrides=[(f"scanners.{config.name}.options.config", str(rules))]
    )

    scanner = scanner_cls(context=context_outside_checkouts, config=config)

    assert scanner.dependency_unavailable_reason is None
    assert _configs(scanner) == [Path(os.path.realpath(rules)).as_posix()]


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

    assert scanner.dependency_unavailable_reason is None
    assert _configs(scanner) == ["p/security"]


@pytest.mark.parametrize(
    "spelling", ["policy", "supply-chain", "secrets", "my-ruleset"]
)
@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_online_passes_a_bare_tool_spelling_as_written(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    monkeypatch,
    spelling,
):
    """A bare token with no path separator and no rule-file suffix is one of the
    tool's own spellings (semgrep's product names, a ruleset name) and reaches the
    tool untouched, as every value did at the base.

    Fails at the tip that read every non-registry value as a local path: such a
    token resolved to nothing and declined the scanner.
    """
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False, config=spelling)),
    )

    assert scanner.dependency_unavailable_reason is None
    assert _configs(scanner) == [spelling]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_bare_name_that_exists_in_the_source_tree_is_a_path_and_is_refused(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """The control for the pass-through: a bare token that names a directory in
    the source tree is what the tool, run there, would read as that directory, so
    it is a path, and an in-tree path is refused; the scanner declines."""
    source_dir = Path(test_plugin_context.source_dir)
    (source_dir / "rules").mkdir(parents=True, exist_ok=True)
    (source_dir / "rules" / "x.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False, config="rules")),
    )

    _declined_for_its_config(scanner, scanner.config.name)
    assert not any("rules" in value for value in _configs(scanner)), _configs(scanner)


@pytest.mark.parametrize("spelling", ["policy", "supply-chain", "secrets"])
@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_a_reserved_product_name_passes_through_beside_a_same_named_directory(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    test_plugin_context,
    monkeypatch,
    spelling,
):
    """semgrep resolves its reserved product names before it reads a value as a
    path, so a ``policy/`` or ``secrets/`` directory in the scanned tree (IAM, OPA
    and Kubernetes repositories carry them) does not turn ``config: policy`` into
    an in-tree path.

    Fails at the tip that judged every bare token by a same-named path's
    existence: the scanner declined with a path-trust refusal naming the
    repository's own directory.
    """
    source_dir = Path(test_plugin_context.source_dir)
    (source_dir / spelling).mkdir(parents=True, exist_ok=True)
    (source_dir / spelling / "x.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False, config=spelling)),
    )

    assert scanner.dependency_unavailable_reason is None
    assert _configs(scanner) == [spelling]


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_online_with_nothing_configured_runs_the_default_rulesets(
    scanner_cls, config_cls, options_cls, cache_env, test_plugin_context, monkeypatch
):
    """The control: the default rulesets are for an empty ``options.config``
    (the option is a string, so "unset" is the empty string), never a substitute
    for one that was set."""
    monkeypatch.delenv(cache_env, raising=False)
    _online(monkeypatch, scanner_cls)

    scanner = scanner_cls(
        context=test_plugin_context,
        config=config_cls(options=options_cls(offline=False, config="")),
    )

    assert scanner.dependency_unavailable_reason is None
    configs = _configs(scanner)
    assert all(value in configs for value in scanner.default_rulesets()), configs


@pytest.mark.parametrize(
    ("scanner_cls", "config_cls", "options_cls", "cache_env"), SCANNERS
)
def test_local_rules_offline_declare_no_content_database(
    scanner_cls,
    config_cls,
    options_cls,
    cache_env,
    context_outside_checkouts,
    tmp_path,
    monkeypatch,
):
    """Fails at the base: offline declared the ruleset whenever the mode was
    offline, so a scan that ran the operator's own rules was graded on the age of
    a cache it never read."""
    rules = _rules_beside_the_tree(context_outside_checkouts)
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "registry.yaml").write_text(RULE, encoding="utf-8")
    monkeypatch.setenv(cache_env, str(cache))

    scanner = scanner_cls(
        context=context_outside_checkouts,
        config=config_cls(options=options_cls(offline=True, config=str(rules))),
    )

    assert scanner.dependency_unavailable_reason is None
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
