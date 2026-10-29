# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The path-refusal warnings show an environment-chosen value as ``<value>``.

``honored_path`` warns when it refuses a path, naming the resolved value. A
configured path can come from the environment (``${VAR}`` interpolation), and
environment values are never logged: the warning shows such a value through
the shown form (``<value>``), as every other message that can quote one does.
A value the environment did not choose is the configuration's own text and
stays named, so the warning keeps its use."""

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
)
from automated_security_helper.config.path_trust import (
    honored_path,
    refused_derived_product,
    reset_path_refusal_warnings,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.utils.log import ASH_LOGGER


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.WARNING)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def _warnings():
    handler = _Records()
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler.messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _layout(tmp_path: Path) -> dict:
    source = tmp_path / "repo"
    source.mkdir()
    work = tmp_path / "out" / ASH_WORK_DIR_NAME
    product = work / "derived.yaml"
    product.parent.mkdir(parents=True)
    product.write_text("")
    return {"source": source, "work": work, "product": product}


def _config_reading(value: str):
    """A config whose environment-read values hold *value*
    (``AshConfig._environment_values``; read by ``config_environment_values``)."""
    return SimpleNamespace(_environment_values=[value])


def test_the_derived_dir_refusal_shows_an_env_chosen_value_as_shown(
    tmp_path, _warnings
):
    layout = _layout(tmp_path)
    value = layout["product"].as_posix()
    refused = honored_path(
        value,
        source_dir=layout["source"],
        key="scanners.standin.options.config_file",
        config=_config_reading(value),
        derived_dirs=(layout["work"],),
        operator_written=False,
    )
    assert refused is None
    named = [m for m in _warnings if "scanners.standin.options.config_file" in m]
    assert named, _warnings
    assert all(value not in m for m in named), named
    assert any("<value>" in m for m in named), named


def test_the_in_tree_refusal_shows_an_env_chosen_value_as_shown(tmp_path, _warnings):
    layout = _layout(tmp_path)
    inside = layout["source"] / "cfg.yaml"
    inside.write_text("")
    value = inside.as_posix()
    refused = honored_path(
        value,
        source_dir=layout["source"],
        key="scanners.standin.options.config_file",
        config=_config_reading(value),
    )
    assert refused is None
    named = [m for m in _warnings if "scanners.standin.options.config_file" in m]
    assert named, _warnings
    assert all(value not in m for m in named), named
    assert any("<value>" in m for m in named), named


def test_a_value_the_environment_did_not_choose_stays_named(tmp_path, _warnings):
    """Control: with no environment-read values the warning still names the
    path, so the refusal stays actionable."""
    layout = _layout(tmp_path)
    inside = layout["source"] / "cfg.yaml"
    inside.write_text("")
    refused = honored_path(
        inside.as_posix(),
        source_dir=layout["source"],
        key="scanners.standin.options.config_file",
        config=SimpleNamespace(_environment_values=[]),
    )
    assert refused is None
    named = [m for m in _warnings if "scanners.standin.options.config_file" in m]
    assert named, _warnings
    assert any(inside.as_posix() in m for m in named), named


def test_a_value_the_caller_read_from_the_environment_is_shown_as_shown(
    tmp_path, _warnings
):
    """A caller that read the value from an environment variable itself says so
    (``env_named``): the warning shows the shown form with no environment-read
    values on the config, and the path is not named."""
    layout = _layout(tmp_path)
    inside = layout["source"] / "cfg.yaml"
    inside.write_text("")
    refused = honored_path(
        inside.as_posix(),
        source_dir=layout["source"],
        key="SOME_INPUT_FILE",
        config=SimpleNamespace(_environment_values=[]),
        env_named=True,
    )
    assert refused is None
    named = [m for m in _warnings if "SOME_INPUT_FILE" in m]
    assert named, _warnings
    for message in named:
        assert inside.as_posix() not in message, message
        assert inside.name not in message, message
    assert any(ENVIRONMENT_VALUE_SHOWN in m for m in named), named


def test_a_derived_product_the_caller_read_from_the_environment_is_shown_as_shown(
    tmp_path, _warnings
):
    layout = _layout(tmp_path)
    value = layout["product"].as_posix()
    refused = refused_derived_product(
        value,
        source_dir=layout["source"],
        key="SOME_INPUT_FILE",
        config=SimpleNamespace(_environment_values=[]),
        derived_dirs=(layout["work"],),
        operator_written=False,
        env_named=True,
    )
    assert refused is True
    named = [m for m in _warnings if "SOME_INPUT_FILE" in m]
    assert named, _warnings
    assert all(value not in m and layout["product"].name not in m for m in named), named
    assert any(ENVIRONMENT_VALUE_SHOWN in m for m in named), named


def test_honored_path_passes_the_callers_environment_claim_to_the_derived_dir_clause(
    tmp_path, _warnings
):
    """The derived-directory refusal reached through ``honored_path`` shows the
    path as the shown form when the caller read the value from the environment."""
    layout = _layout(tmp_path)
    value = layout["product"].as_posix()
    refused = honored_path(
        value,
        source_dir=layout["source"],
        key="SOME_INPUT_FILE",
        config=SimpleNamespace(_environment_values=[]),
        derived_dirs=(layout["work"],),
        operator_written=False,
        env_named=True,
    )
    assert refused is None
    named = [m for m in _warnings if "SOME_INPUT_FILE" in m]
    assert named, _warnings
    assert all(value not in m and layout["product"].name not in m for m in named), named
    assert any(ENVIRONMENT_VALUE_SHOWN in m for m in named), named


def test_the_derived_dir_refusal_through_honored_path_names_a_value_not_from_the_environment(
    tmp_path, _warnings
):
    """Control: without the caller's claim the same refusal names the path."""
    layout = _layout(tmp_path)
    value = layout["product"].as_posix()
    refused = honored_path(
        value,
        source_dir=layout["source"],
        key="SOME_INPUT_FILE",
        config=SimpleNamespace(_environment_values=[]),
        derived_dirs=(layout["work"],),
        operator_written=False,
        env_named=False,
    )
    assert refused is None
    named = [m for m in _warnings if "SOME_INPUT_FILE" in m]
    assert named, _warnings
    assert any(value in m for m in named), named


def test_an_operator_written_value_read_from_the_environment_is_handed_over_unwarned(
    tmp_path, _warnings
):
    """The environment claim names how a refusal is shown; it does not make a
    refusal: an operator-written derived path is honored, with no warning."""
    layout = _layout(tmp_path)
    honored = honored_path(
        layout["product"].as_posix(),
        source_dir=layout["source"],
        key="SOME_INPUT_FILE",
        config=SimpleNamespace(_environment_values=[]),
        derived_dirs=(layout["work"],),
        operator_written=True,
        env_named=True,
    )
    assert honored == layout["product"].resolve()
    assert not [m for m in _warnings if "SOME_INPUT_FILE" in m], _warnings


def test_a_value_the_environment_read_elsewhere_does_not_hide_this_path(
    tmp_path, _warnings
):
    """Control: the config chain read a non-empty value, but it does not appear
    in the refused path, so the warning still names the literal path."""
    layout = _layout(tmp_path)
    inside = layout["source"] / "cfg.yaml"
    inside.write_text("")
    refused = honored_path(
        inside.as_posix(),
        source_dir=layout["source"],
        key="scanners.standin.options.config_file",
        config=_config_reading("some-other-environment-value"),
    )
    assert refused is None
    named = [m for m in _warnings if "scanners.standin.options.config_file" in m]
    assert named, _warnings
    assert any(inside.as_posix() in m for m in named), named
    assert all("<value>" not in m for m in named), named


def _unnormalized_in_tree_spelling(layout: dict) -> tuple:
    """A value inside the scanned tree whose written spelling differs from the
    path it resolves to: (written spelling, resolved path)."""
    resolved = layout["source"] / "marker-trust-value"
    resolved.write_text("")
    written = f"{layout['source'].as_posix()}/./marker-trust-dir/../marker-trust-value"
    assert written != resolved.as_posix()
    return written, resolved


def test_a_value_read_from_the_environment_is_not_shown_in_its_own_spelling(
    tmp_path, _warnings
):
    layout = _layout(tmp_path)
    written, _resolved = _unnormalized_in_tree_spelling(layout)
    refused = honored_path(
        written,
        source_dir=layout["source"],
        key="SOME_INPUT_FILE",
        config=SimpleNamespace(_environment_values=[]),
        env_named=True,
    )
    assert refused is None
    named = [m for m in _warnings if "SOME_INPUT_FILE" in m]
    assert named, _warnings
    assert all(written not in m for m in named), named


def test_an_operator_written_value_with_a_different_spelling_names_its_resolved_path(
    tmp_path, _warnings
):
    """Control: the same value, not read from the environment, is named by the
    path it resolves to."""
    layout = _layout(tmp_path)
    written, resolved = _unnormalized_in_tree_spelling(layout)
    refused = honored_path(
        written,
        source_dir=layout["source"],
        key="SOME_INPUT_FILE",
        config=SimpleNamespace(_environment_values=[]),
        env_named=False,
    )
    assert refused is None
    named = [m for m in _warnings if "SOME_INPUT_FILE" in m]
    assert named, _warnings
    assert any(resolved.as_posix() in m for m in named), named
