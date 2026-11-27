"""The apply reports the operator it applied, and every reader tells them apart.

``_apply_config_override`` returns the key segments it landed on, the parsed value
and, as its third item, what the override did. That item was a bool, whether the
override appended. With ``KEY-=VALUE`` there are three outcomes, so it is the
operator: ``REPLACE`` for a set (a ``+=`` onto a value that is no list sets that
value, so it is one), ``APPEND`` for an append to a list or a list started, and
``REMOVE`` for a removal. Each operator is a non-empty string, so a reader that
still tests the item for truth reads every override as an append.

The controls here go red under such a reader. A replacement is recorded as a field
the operator wrote, and an append or a removal is not: ``ash report`` and ``ash merge``
take a field from the operator only when the record says the operator wrote it, and
an override that only edits a list supplies none. The cure that sets a string option
back to the text a replacement typed (``007`` parses as the number 7) still applies.
"""

from __future__ import annotations

import copy

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.recorded_config import (
    _sets,
    written_field_paths,
)
from automated_security_helper.config.resolve_config import (
    _apply_config_override,
    apply_config_overrides,
)

pytestmark = pytest.mark.unit

#: A typed list option with a one-item default and no minimum length, so a removal
#: can take its item out and leave the configuration valid.
KEY = "scanners.checkov.options.additional_formats"
SEGMENTS = KEY.split(".")


def _additional_formats(config: AshConfig) -> list[str]:
    """The formats the configuration asks checkov for beside its JSON report."""
    return list(config.scanners.checkov.options.additional_formats)


@pytest.mark.parametrize(
    ("written", "key", "value", "operator_name", "after"),
    [
        pytest.param(
            {"project_name": "old"},
            "project_name",
            "new",
            "REPLACE",
            {"project_name": "new"},
            id="set",
        ),
        pytest.param(
            {"ash_plugin_modules": ["a"]},
            "ash_plugin_modules+",
            "b",
            "APPEND",
            {"ash_plugin_modules": ["a", "b"]},
            id="append",
        ),
        pytest.param(
            {"ash_plugin_modules": None},
            "ash_plugin_modules+",
            "[a, b]",
            "APPEND",
            {"ash_plugin_modules": ["a", "b"]},
            id="start-from-none",
        ),
        pytest.param(
            {"project_name": "old"},
            "project_name+",
            "new",
            "REPLACE",
            {"project_name": "new"},
            id="append-to-a-value",
        ),
        pytest.param(
            {"ash_plugin_modules": ["a", "b", "a"]},
            "ash_plugin_modules-",
            "a",
            "REMOVE",
            {"ash_plugin_modules": ["b"]},
            id="remove",
        ),
    ],
)
def test_the_apply_reports_the_operator_it_applied(
    written, key, value, operator_name, after
):
    """The key is the part of the entry before its first ``=``, the operator's
    character still on it, as ``apply_config_overrides`` passes it."""
    from automated_security_helper.utils.override_key import APPEND, REMOVE, REPLACE

    operators = {"REPLACE": REPLACE, "APPEND": APPEND, "REMOVE": REMOVE}
    document = copy.deepcopy(written)

    assert _apply_config_override(document, key, value)[2] == operators[operator_name]
    assert document == after, "control: the case applies what its id says"


def test_a_replacement_is_recorded_as_written():
    """A replacement writes the field, so the record the apply stamps holds it, and a
    command that takes a field from the operator only when the operator wrote it
    takes this one."""
    config = apply_config_overrides(AshConfig(), [f'{KEY}=["sarif"]'])

    assert _additional_formats(config) == ["sarif"], "control: the override applied"
    assert _sets(config, SEGMENTS)


def test_an_append_is_not_recorded_as_written():
    """An append adds to whatever list the configuration held, here the option's
    default, so it writes no field: the record is the one the configuration had."""
    base = AshConfig()

    config = apply_config_overrides(base, [f'{KEY}+=["sarif"]'])

    appended = _additional_formats(config)
    assert appended == ["cyclonedx_json", "sarif"], "control: the append applied"
    assert not _sets(config, SEGMENTS)
    assert config._written_before_overrides == written_field_paths(base)


def test_a_removal_is_not_recorded_as_written():
    """A removal takes items out of whatever list the configuration held, as an
    append adds to it, so it writes no field either."""
    base = AshConfig()

    config = apply_config_overrides(base, [f'{KEY}-=["cyclonedx_json"]'])

    assert _additional_formats(config) == [], "control: the removal applied"
    assert not _sets(config, SEGMENTS)
    assert config._written_before_overrides == written_field_paths(base)


@pytest.mark.parametrize(
    "override",
    ["project_name=007", "project_name+=007"],
    ids=["set", "append-to-a-value"],
)
def test_the_retype_cure_still_applies_to_a_replacement(override):
    """``007`` parses as the number 7, which the string option refuses, and the cure
    sets the option to the text the override typed. A ``+=`` onto the option's
    string sets it too, so the cure applies to it as to a set."""
    config = apply_config_overrides(AshConfig(project_name="demo"), [override])

    assert config.project_name == "007"
