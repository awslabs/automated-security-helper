"""``-=`` at a key where the configuration holds no list.

A removal takes items out of a list the configuration holds and makes nothing it
does not find. Where the key holds no list, what happens depends on why:

- a typed setting that is not set holds None and keeps it; the removal removes
  nothing, and the run's own application says so once in a run;
- an option of a section that no plugin ASH ships reads has no default to remove
  items from; nothing is written, and the run's own application says so once in a
  run;
- an option no file wrote, of a section a shipped plugin reads, starts from the
  option's default, as ``+=`` does, so the removal reaches the list the plugin
  reads;
- an option of such a section that the plugin's row of defaults does not name is
  no list option of the plugin (it is misspelled, or holds a single value), so the
  run's own application refuses the removal, naming the key;
- a key the configuration has no setting for is refused, naming the key.

Only the application that builds the run's own configuration refuses or warns. A
replay of the same overrides onto another base (the trusted views, the gates) can
meet a base that holds less than the run's own document, so there a removal that
finds no list changes nothing and says nothing.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugin_manifests import UNTYPED_LIST_OPTION_DEFAULTS
from automated_security_helper.utils.log import run_log_scope

pytestmark = pytest.mark.unit

#: A typed setting that is None unless a configuration sets it.
NETWORK_SCANNERS = "sandbox.network_scanners"
#: An option of trivy-repo, a plugin ASH ships whose section the configuration does
#: not type.
TRIVY_REPO_SCANNERS = "scanners.trivy-repo.options.scanners"
#: An option of bedrock-summary-reporter, a reporter ASH ships whose section the
#: configuration does not type either: the scanner types its summary leaves out.
BEDROCK_EXCLUDED_TYPES = (
    "reporters.bedrock-summary-reporter.options.exclude_scanner_types"
)
#: trivy-repo's ``scanners`` misspelled, and an option of trivy-repo that holds a
#: single value: the plugin has no list option at either key.
TRIVY_REPO_MISSPELLED = "scanners.trivy-repo.options.scaners"
TRIVY_REPO_SCALAR = "scanners.trivy-repo.options.license_full"
#: A key whose ``+=`` lands in a section no plugin ASH ships reads, which the run's
#: own application warns of. A test that finds no warning for its own key applies it
#: in the same capture, so the empty result is a measurement.
_CONTROL = "reporters.acme-capture-exporter.options.destinations"


def _resolve_config_module():
    """The module itself, whose sets of notices given the fixture below resets."""
    return importlib.import_module("automated_security_helper.config.resolve_config")


@pytest.fixture(autouse=True)
def _each_test_starts_with_no_notice_given(monkeypatch):
    """Each test starts with no override notice given and no unread-section append
    warned of, and the module's own sets are put back after it. ``raising=False``
    for the notice set, which the removal form adds: without it the tests still run
    to what they check."""
    module = _resolve_config_module()
    monkeypatch.setattr(module, "_OVERRIDE_NOTICES_GIVEN", set(), raising=False)
    monkeypatch.setattr(module, "_APPEND_TO_UNREAD_SECTION_WARNED", set())


def _warnings_naming(caplog, key: str) -> list[str]:
    """The texts of the warnings the test captured that name *key*."""
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and key in record.getMessage()
    ]


def _warn_of_the_control() -> None:
    """Have the run's own application give the capture control's one warning."""
    apply_config_overrides(
        AshConfig(), [f'{_CONTROL}+=["x"]'], warn_unread_appends=True
    )


def test_a_removal_from_a_setting_that_is_not_set_removes_nothing_and_says_so_once(
    caplog,
):
    """``sandbox.network_scanners`` holds None until a configuration sets it, and each
    scanner's own network need applies then. A removal leaves it None, and the run's
    own application says that the removal removed nothing, once in the run however
    often the run applies its overrides."""
    with caplog.at_level("WARNING", logger="ash"):
        with run_log_scope():
            for _ in range(2):
                config = apply_config_overrides(
                    AshConfig(),
                    [f'{NETWORK_SCANNERS}-=["grype"]'],
                    warn_unread_appends=True,
                )

    assert config.sandbox.network_scanners is None
    named = _warnings_naming(caplog, NETWORK_SCANNERS)
    assert len(named) == 1, named
    assert "removes nothing" in named[0], named
    assert "is not set" in named[0], named


def test_a_removal_in_a_section_no_shipped_plugin_reads_removes_nothing_and_says_so_once(
    caplog,
):
    """No plugin ASH ships reads the section, so there is no default to remove items
    from: nothing is written, not even the section, and the run's own application
    says so once in the run. It is the one warning that names the key: the warning
    for an append to such a section, whose set is reset for this test, says nothing
    here."""
    key = "scanners.acme-unread-linter.options.rules"

    with caplog.at_level("WARNING", logger="ash"):
        with run_log_scope():
            for _ in range(2):
                config = apply_config_overrides(
                    AshConfig(),
                    [f'{key}-=["typosquatting"]'],
                    warn_unread_appends=True,
                )

    assert "acme-unread-linter" not in (config.scanners.model_extra or {})
    named = _warnings_naming(caplog, key)
    assert len(named) == 1, named
    assert "has no default to remove items from" in named[0], named


@pytest.mark.parametrize(
    ("key", "kind", "item", "own_configuration"),
    [
        pytest.param(TRIVY_REPO_SCANNERS, "scanner", "secret", True, id="own-build"),
        pytest.param(TRIVY_REPO_SCANNERS, "scanner", "secret", False, id="replay"),
        pytest.param(
            BEDROCK_EXCLUDED_TYPES, "reporter", "SECRET", True, id="reporter-own-build"
        ),
        pytest.param(
            BEDROCK_EXCLUDED_TYPES, "reporter", "SECRET", False, id="reporter-replay"
        ),
    ],
)
def test_a_removal_from_an_untyped_option_starts_from_its_shipped_default(
    key, kind, item, own_configuration
):
    """Neither trivy-repo's section nor bedrock-summary-reporter's is a typed field
    of the configuration, so the document holds only what a file wrote, and no file
    wrote these options. Both plugins ship with ASH and each option's default is a
    row of the table ``+=`` starts from: the removal takes the item out of that
    default (``secret`` out of trivy-repo's scanners; ``SECRET`` out of the scanner
    types the reporter leaves out of its summary, so it leaves out none), and the
    list lands where the plugin reads it, in the run's own build and in a replay
    alike."""
    segment, plugin, *option = key.split(".")
    default = list(UNTYPED_LIST_OPTION_DEFAULTS[segment][plugin][tuple(option)])
    kept = [entry for entry in default if entry != item]
    assert len(kept) < len(default), "control: the default holds the item removed"

    config = apply_config_overrides(
        AshConfig(),
        [f'{key}-=["{item}"]'],
        warn_unread_appends=own_configuration,
    )

    written = {"options": {option[-1]: kept}}
    assert config.model_dump()[segment][plugin] == written
    assert config.get_plugin_config(kind, plugin) == written


@pytest.mark.parametrize(
    "key",
    [
        pytest.param("no_such_setting", id="top-level"),
        pytest.param("scanners.trivy.options.scanner", id="typed-option"),
    ],
)
def test_a_removal_at_a_key_the_configuration_lacks_is_refused(key):
    """The configuration has no setting at the key, at the top level or inside a
    typed section (trivy's option is ``scanners``), so there is no list that could
    hold the items. The run's own application refuses the removal, naming the key,
    where it would otherwise remove nothing from a misspelled key and say nothing."""
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(), [f'{key}-=["vuln"]'], warn_unread_appends=True
        )

    text = str(refused.value)
    assert "has no setting" in text, text
    assert key in text, text


@pytest.mark.parametrize(
    ("written", "key"),
    [
        pytest.param([], TRIVY_REPO_MISSPELLED, id="misspelled-option"),
        pytest.param(
            ["scanners.trivy-repo.enabled=true"],
            TRIVY_REPO_MISSPELLED,
            id="misspelled-option-in-a-written-section",
        ),
        pytest.param([], TRIVY_REPO_SCALAR, id="option-that-is-no-list"),
    ],
)
def test_a_removal_at_an_option_its_shipped_plugin_has_no_list_at_is_refused(
    written, key
):
    """trivy-repo ships with ASH, and its row of the table ``+=`` starts from names
    every list option the plugin has. An option the row does not name is no list
    option of it: misspelled (``scaners``), or holding a single value
    (``license_full``). The run's own application refuses the removal, naming the
    key and never the items, where it would otherwise remove nothing and say
    nothing, whether or not an earlier override wrote the plugin's section."""
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(), [*written, f'{key}-=["vuln"]'], warn_unread_appends=True
        )

    text = str(refused.value)
    assert f"'{key}-='" in text, text
    assert "has no list option" in text, text
    assert "vuln" not in text, text


def _network_scanners(config: AshConfig) -> Any:
    return config.sandbox.network_scanners


def _the_replayed_section(config: AshConfig) -> Any:
    return (config.scanners.model_extra or {}).get("acme-replayed-linter")


def _trivy_options(config: AshConfig) -> Any:
    options = config.scanners.trivy.options
    return sorted(options.model_extra or {}), list(options.scanners)


def _the_trivy_repo_section(config: AshConfig) -> Any:
    return (config.scanners.model_extra or {}).get("trivy-repo")


@pytest.mark.parametrize(
    ("key", "items", "read"),
    [
        pytest.param(NETWORK_SCANNERS, '["grype"]', _network_scanners, id="typed-none"),
        pytest.param(
            "scanners.acme-replayed-linter.options.rules",
            '["typosquatting"]',
            _the_replayed_section,
            id="unread-section",
        ),
        pytest.param(
            "scanners.trivy.options.scanner",
            '["vuln"]',
            _trivy_options,
            id="absent-option",
        ),
        pytest.param(
            TRIVY_REPO_MISSPELLED,
            '["vuln"]',
            _the_trivy_repo_section,
            id="option-its-shipped-plugin-has-no-list-at",
        ),
    ],
)
def test_a_replay_of_a_removal_that_finds_no_list_says_nothing(
    caplog, key, items, read
):
    """A replay applies the overrides to a base that can hold less than the run's
    own document, so a removal that finds no list is neither refused nor warned of
    there, and the setting is as the base held it."""
    with caplog.at_level("WARNING", logger="ash"):
        config = apply_config_overrides(AshConfig(), [f"{key}-={items}"])
        _warn_of_the_control()

    assert read(config) == read(AshConfig())
    assert _warnings_naming(caplog, key) == []
    assert len(_warnings_naming(caplog, _CONTROL)) == 1, "control: the capture works"
