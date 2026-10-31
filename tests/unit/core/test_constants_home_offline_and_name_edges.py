# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of ``core/constants.py``, each red on the tree that carried it.

* An asset that does not decode killed the import: ``UnicodeDecodeError`` is not
  an ``OSError``.
* The once-only warning was a check then an add, so two threads both logged it.
* A HOME of ``/`` was a home, so ``~/.ash/bin`` was ``/.ash/bin`` and ``~/x``
  expanded to ``//x``; an unset HOME and an empty one shared one warning key.
* An ASH_BIN_PATH of ``~/bin`` was read as a relative path, so the directory
  ``ash dependencies install`` filled was never searched.
* An empty ASH_DEFAULT_SEVERITY_LEVEL warned on every start.
* A secret word followed by a qualifier glued on (``GITHUBTOKENPROD``,
  ``MYPASSWORDV2``, ``KEY2PROD``) and an ``AUTHORIZATION`` name were not
  secret-shaped.
* ASH_OFFLINE with a blank around it ran online, and an unrecognized value said
  nothing.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import constants
from automated_security_helper.core.constants import (
    ash_bin_path_from_environment,
    expand_home,
    is_offline_mode,
    is_refused_config_environment_name,
    is_secret_shaped_environment_name,
    usable_home,
    warn_if_home_unusable,
    warn_relative_value_once,
)

pytestmark = pytest.mark.unit

posix_only = pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")


@pytest.fixture
def logger(monkeypatch):
    """A fresh once-only record, and a logger that counts what ASH warns."""
    monkeypatch.setattr(constants, "_warned_relative_values", set())
    from automated_security_helper.utils import log as ash_log

    recorder = MagicMock()
    monkeypatch.setattr(ash_log, "ASH_LOGGER", recorder)
    return recorder


def test_an_asset_that_does_not_decode_reads_as_absent(tmp_path):
    asset = tmp_path / "ASH_INSTALLED_REVISION"
    # Not text in UTF-8, and not defined in cp1252 either, so any locale refuses it.
    asset.write_bytes(b"\x81\x8d\x8f\x90\x9d")

    # Red at the base: UnicodeDecodeError.
    assert constants._installed_revision(asset) == "unknown-commit"


def test_a_readable_asset_still_gives_its_revision(tmp_path):
    asset = tmp_path / "ASH_INSTALLED_REVISION"
    asset.write_text("revision-one\n", encoding="utf-8")

    assert constants._installed_revision(asset) == "revision-one"


def test_two_threads_log_a_once_only_warning_once(monkeypatch, logger):
    barrier = threading.Barrier(2)

    class SlowSet(set):
        """Lets a second thread in between the check and the add, if it can."""

        def __contains__(self, item):
            found = super().__contains__(item)
            try:
                barrier.wait(timeout=0.5)
            except threading.BrokenBarrierError:
                pass
            return found

    monkeypatch.setattr(constants, "_warned_relative_values", SlowSet())

    def call():
        warn_relative_value_once("SOME_VARIABLE", "a/relative/value", "ignored")

    threads = [threading.Thread(target=call) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)

    # Red at the base: both threads saw "not warned yet" and both logged.
    assert logger.warning.call_count == 1


@posix_only
class TestARootHome:
    def test_it_is_no_home(self, monkeypatch):
        monkeypatch.setenv("HOME", "/")

        # Red at the base: Path("/").
        assert usable_home() is None

    def test_a_tilde_path_under_it_expands_to_nothing(self, monkeypatch, logger):
        monkeypatch.setenv("HOME", "/")

        # Red at the base: "//x".
        assert expand_home("~/x") is None

    def test_an_absolute_home_is_still_a_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))

        assert usable_home() == tmp_path
        assert expand_home("~/x") == f"{tmp_path}/x"

    def test_the_warning_names_the_root(self, monkeypatch, logger):
        monkeypatch.setenv("HOME", "/")

        warn_if_home_unusable()

        message = logger.warning.call_args.args[0]
        assert "HOME is the filesystem root" in message
        assert "other than the filesystem root" in message

    def test_an_unset_home_and_an_empty_one_each_get_their_warning(
        self, monkeypatch, logger
    ):
        import pwd

        def no_passwd_entry(uid):
            raise KeyError(uid)

        monkeypatch.setattr(pwd, "getpwuid", no_passwd_entry)
        monkeypatch.delenv("HOME", raising=False)
        warn_if_home_unusable()
        monkeypatch.setenv("HOME", "")
        warn_if_home_unusable()

        # Red at the base: both were keyed ("HOME", ""), so the second was dropped.
        messages = [call.args[0] for call in logger.warning.call_args_list]
        assert len(messages) == 2
        assert "HOME is not set" in messages[0]
        assert "HOME is empty" in messages[1]


@posix_only
class TestABinPathUnderTilde:
    def test_it_is_expanded_from_the_usable_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("ASH_BIN_PATH", "~/tools/bin")

        # Red at the base: the literal, relative "~/tools/bin".
        assert ash_bin_path_from_environment() == str(Path(tmp_path) / "tools" / "bin")

    def test_a_bare_tilde_is_the_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("ASH_BIN_PATH", "~")

        assert ash_bin_path_from_environment() == str(tmp_path)

    def test_without_a_usable_home_it_reads_as_unset(self, monkeypatch, logger):
        monkeypatch.setenv("HOME", "")
        monkeypatch.setenv("ASH_BIN_PATH", "~/tools/bin")

        assert ash_bin_path_from_environment() is None

    def test_an_absolute_value_is_returned_as_set(self, monkeypatch):
        monkeypatch.setenv("ASH_BIN_PATH", "/opt/ash/bin")

        assert ash_bin_path_from_environment() == "/opt/ash/bin"


class TestAnEmptySeverityLevel:
    def test_it_is_an_unset_one(self, caplog):
        with caplog.at_level(logging.WARNING, logger=constants.__name__):
            level = constants._resolve_default_severity_level("")
            blank = constants._resolve_default_severity_level("   ")

        # Red at the base: a warning on every start.
        assert level == blank == "MEDIUM"
        assert caplog.records == []

    def test_a_value_that_names_no_threshold_still_warns(self, caplog):
        with caplog.at_level(logging.WARNING, logger=constants.__name__):
            level = constants._resolve_default_severity_level("INFO")

        assert level == "MEDIUM"
        assert len(caplog.records) == 1


@pytest.mark.parametrize(
    "name",
    [
        "ASH_GITHUBTOKENPROD",
        "ASH_MYPASSWORDV2",
        "ASH_X_KEY2PROD",
        "ASH_TOKEN1DEV",
        "ASH_AUTHORIZATION",
        "ASH_X_AUTHORIZATIONS",
        "ASH_X_AUTHORIZATION_PROD",
    ],
)
def test_a_glued_qualifier_or_an_authorization_name_is_secret_shaped(name):
    # Red at the base: none was matched by either reading.
    assert is_secret_shaped_environment_name(name) is True
    assert is_refused_config_environment_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "ASH_AUTHORIZATION_ENABLED",
        "ASH_BYPASSDEV",
        "ASH_PASSPORTDEV",
        "ASH_TEST",
        "ASH_COMPAT_2",
    ],
)
def test_the_controls_do_not_become_secret_shaped(name):
    """A flag named after the word, the denylisted segments and look-alikes."""
    assert is_secret_shaped_environment_name(name) is False


class TestOfflineMode:
    @pytest.mark.parametrize(
        "value", [" yes", "YES\n", "true ", "\t1", "Yes", "TRUE", "1"]
    )
    def test_the_offline_values_count_with_blanks_around_them(
        self, monkeypatch, logger, value
    ):
        monkeypatch.setenv("ASH_OFFLINE", value)

        # Red at the base for the padded ones: read as online.
        assert is_offline_mode() is True
        logger.warning.assert_not_called()

    @pytest.mark.parametrize("value", ["NO", "no ", "false", "0", "off", ""])
    def test_a_plain_no_is_online_and_says_nothing(self, monkeypatch, logger, value):
        monkeypatch.setenv("ASH_OFFLINE", value)

        assert is_offline_mode() is False
        logger.warning.assert_not_called()

    def test_unset_is_online_and_says_nothing(self, monkeypatch, logger):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)

        assert is_offline_mode() is False
        logger.warning.assert_not_called()

    def test_an_unrecognized_value_is_online_and_said_once(self, monkeypatch, logger):
        monkeypatch.setenv("ASH_OFFLINE", "enabled")

        assert is_offline_mode() is False
        assert is_offline_mode() is False

        # Red at the base: nothing said.
        logger.warning.assert_called_once()
        assert (
            "ASH_OFFLINE='enabled' is not recognized"
            in logger.warning.call_args.args[0]
        )
