# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``refuse_a_named_config_that_does_not_exist``: the refusal ``ash plugin list`` and
``ash dependencies install`` make before they resolve a config.

``resolve_config`` answers a named path that does not exist with the default
configuration, so each command asks first. The helper refuses a path whose stat
says it is missing, in the words ``ash report`` uses, and leaves every other case to
``resolve_config``: no value, a blank one, the file ASH_CONFIG names, and a path
that exists whatever it is.
"""

from __future__ import annotations

import sys

import pytest

from automated_security_helper.config.named_config import (
    refuse_a_named_config_that_does_not_exist,
)
from automated_security_helper.core.exceptions import (
    ASHConfigFileNotFoundError,
    ASHConfigValidationError,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def test_a_path_that_is_not_there_is_refused_by_name(tmp_path):
    missing = tmp_path / "missing.yaml"

    with pytest.raises(ASHConfigFileNotFoundError) as refusal:
        refuse_a_named_config_that_does_not_exist(str(missing))

    message = str(refusal.value)
    assert message.startswith("Configuration file not found: "), message
    assert missing.as_posix() in message, message


def test_the_refusal_is_a_config_validation_error(tmp_path):
    """The commands' own handlers for an invalid configuration (exit 3) take it."""
    with pytest.raises(ASHConfigValidationError):
        refuse_a_named_config_that_does_not_exist(str(tmp_path / "missing.yaml"))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symbolic links and names")
def test_a_link_to_nothing_is_refused(tmp_path):
    link = tmp_path / "link.yaml"
    link.symlink_to(tmp_path / "gone.yaml")

    with pytest.raises(ASHConfigFileNotFoundError):
        refuse_a_named_config_that_does_not_exist(str(link))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
def test_a_name_with_a_newline_is_shown_on_one_line(tmp_path):
    with pytest.raises(ASHConfigFileNotFoundError) as refusal:
        refuse_a_named_config_that_does_not_exist(str(tmp_path / "a\nmissing.yaml"))

    message = str(refusal.value)
    assert "\n" not in message, message
    assert "missing.yaml" in message, message


@pytest.mark.parametrize("config", [None, "", "   ", "\t\n"])
def test_no_value_and_a_blank_one_are_left_to_resolve_config(config):
    assert refuse_a_named_config_that_does_not_exist(config) is None


def test_a_file_that_exists_is_not_refused(tmp_path):
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    assert refuse_a_named_config_that_does_not_exist(str(config)) is None


def test_a_directory_is_left_to_resolve_config(tmp_path):
    """It exists, so it is not this refusal's; resolve_config says it is no file."""
    assert refuse_a_named_config_that_does_not_exist(str(tmp_path)) is None


def test_the_file_ash_config_names_is_left_to_resolve_config(tmp_path, monkeypatch):
    """``get_default_config`` refuses it in the words reserved for ASH_CONFIG."""
    missing = str(tmp_path / "from-env.yaml")
    monkeypatch.setenv("ASH_CONFIG", missing)

    assert refuse_a_named_config_that_does_not_exist(missing) is None


def test_another_missing_path_is_refused_while_ash_config_is_set(tmp_path, monkeypatch):
    """Only the path ASH_CONFIG itself names is passed over."""
    monkeypatch.setenv("ASH_CONFIG", str(tmp_path / "from-env.yaml"))

    with pytest.raises(ASHConfigFileNotFoundError):
        refuse_a_named_config_that_does_not_exist(str(tmp_path / "other.yaml"))
