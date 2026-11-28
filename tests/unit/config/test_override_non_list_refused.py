"""``-=`` and ``+=`` on a setting that holds a single value or a mapping.

``-=`` removes items from a list, so a value that is no list has nothing for it to
take out. The application that builds the run's own configuration refuses the
removal, naming the key. A replay of the same overrides onto another base (the
trusted views, the gates) applies them to a document that can hold less than the
run's own, so there the removal changes nothing and is not refused.

``+=`` on such a value replaces it, as ``=`` does, before this change and after it.
The run's own application now also says, once in each run, that this is deprecated:
from 4.0 the append is refused. A replay says nothing.

trivy's ``license_full`` is the setting these cases edit: a bool, False by default.
"""

from __future__ import annotations

import importlib
import logging

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import current_run_log_scope, run_log_scope

pytestmark = pytest.mark.unit

KEY = "scanners.trivy.options.license_full"
#: Another bool of the same section, for the case that each key is said once.
OTHER = "scanners.trivy.options.ignore_unfixed"
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


def _append_deprecations(caplog, key: str) -> list[str]:
    """The captured warnings that say ``key+=`` on a value that is no list is
    deprecated."""
    return [
        text
        for text in _warnings_naming(caplog, key)
        if "Deprecated:" in text and f"'{key}+='" in text and "from 4.0" in text
    ]


def _warn_of_the_control() -> None:
    """Have the run's own application give the capture control's one warning."""
    apply_config_overrides(
        AshConfig(), [f'{_CONTROL}+=["x"]'], warn_unread_appends=True
    )


def test_a_removal_from_a_single_value_is_refused_naming_the_key():
    """A bool holds no items to take out. The run's own application refuses the
    removal, naming the key with its operator and saying why."""
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(AshConfig(), [f"{KEY}-=true"], warn_unread_appends=True)

    text = str(refused.value)
    assert f"'{KEY}-='" in text, text
    assert "is not a list" in text, text


def test_a_removal_from_a_mapping_is_refused_naming_the_key():
    """A plugin's options are a mapping, not a list: the removal is refused as it is
    for a single value, naming the key of the mapping."""
    key = "scanners.trivy.options"

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(), [f'{key}-=["license_full"]'], warn_unread_appends=True
        )

    text = str(refused.value)
    assert f"'{key}-='" in text, text
    assert "is not a list" in text, text


def test_an_append_to_a_single_value_replaces_it_and_says_it_is_deprecated(caplog):
    """The append sets the value, as before, and the run's own application gives one
    warning for the key: the deprecation of the append."""
    with caplog.at_level("WARNING", logger="ash"):
        config = apply_config_overrides(
            AshConfig(), [f"{KEY}+=true"], warn_unread_appends=True
        )

    assert config.scanners.trivy.options.license_full is True
    named = _warnings_naming(caplog, KEY)
    assert len(named) == 1, named
    assert _append_deprecations(caplog, KEY) == named


def test_the_append_deprecation_is_said_once_per_run(caplog):
    """A run applies its own overrides more than once (a workspace scan applies them
    to each project): the line is said once for each key in a run, and said again in
    the next run in the same process."""
    with caplog.at_level("WARNING", logger="ash"):
        with run_log_scope():
            first_run = current_run_log_scope()
            for _ in range(2):
                apply_config_overrides(
                    AshConfig(),
                    [f"{KEY}+=true", f"{OTHER}+=true"],
                    warn_unread_appends=True,
                )
            within_the_first_run = len(_append_deprecations(caplog, KEY))
        with run_log_scope():
            second_run = current_run_log_scope()
            apply_config_overrides(
                AshConfig(), [f"{KEY}+=true"], warn_unread_appends=True
            )

    assert first_run is not None and second_run is not None, "control: in a run"
    assert first_run != second_run, "control: two runs are two scopes"
    assert within_the_first_run == 1
    assert len(_append_deprecations(caplog, OTHER)) == 1, "a key of its own"
    assert len(_append_deprecations(caplog, KEY)) == 2


def test_a_replay_of_an_append_to_a_single_value_says_nothing(caplog):
    """Control: an application that does not build the run's own configuration (a
    trusted view, a gate) sets the value and says nothing about the key, before the
    change and after it."""
    with caplog.at_level("WARNING", logger="ash"):
        config = apply_config_overrides(AshConfig(), [f"{KEY}+=true"])
        _warn_of_the_control()

    assert config.scanners.trivy.options.license_full is True
    assert _warnings_naming(caplog, KEY) == []
    assert len(_warnings_naming(caplog, _CONTROL)) == 1, "control: the capture works"


def test_a_removal_from_a_single_value_outside_the_runs_own_configuration_changes_nothing(
    caplog,
):
    """A replay applies the overrides to a base that can hold less than the run's own
    document, so there a removal that finds no list is not refused: the value stays
    as the overrides before it left it, and nothing is said about the key."""
    with caplog.at_level("WARNING", logger="ash"):
        config = apply_config_overrides(AshConfig(), [f"{KEY}=true", f"{KEY}-=true"])
        _warn_of_the_control()

    assert config.scanners.trivy.options.license_full is True
    assert _warnings_naming(caplog, KEY) == []
    assert len(_warnings_naming(caplog, _CONTROL)) == 1, "control: the capture works"


def test_a_replacement_of_a_single_value_is_unchanged(caplog):
    """Control: ``=`` sets the value in the run's own application and says nothing
    about the key, before the change and after it."""
    with caplog.at_level("WARNING", logger="ash"):
        config = apply_config_overrides(
            AshConfig(), [f"{KEY}=true"], warn_unread_appends=True
        )
        _warn_of_the_control()

    assert config.scanners.trivy.options.license_full is True
    assert _warnings_naming(caplog, KEY) == []
    assert len(_warnings_naming(caplog, _CONTROL)) == 1, "control: the capture works"
