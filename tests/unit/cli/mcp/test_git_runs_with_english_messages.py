# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Git runs with English messages whatever the server's locale.

Why this file exists
--------------------
A delivery reads git's message to tell a full disk from another failure
(``_DISK_FULL_MESSAGES`` matches English text). The environment git runs with is
built from an allowlist that passes ``LANG``, ``LC_ALL`` and ``LC_MESSAGES`` through,
so under a locale such as ``de_DE.UTF-8`` git, and the C library's error strings,
were translated and the advice for a full disk never appeared.

What the code does now
----------------------
``_git_environment`` sets ``LC_MESSAGES=C``. ``LC_ALL`` outranks ``LC_MESSAGES``, so
an inherited ``LC_ALL`` is passed on as ``LC_CTYPE``: the categories that decide how
git handles text keep the server's setting, and only the language of the messages is
pinned. ``LANGUAGE``, which gettext reads before the locale's own messages, is not
in the allowlist and is not passed on.

How the tests work
------------------
The function is called with the process environment replaced; no process starts.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def a_german_server(monkeypatch) -> None:
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("LC_MESSAGES", "de_DE.UTF-8")
    monkeypatch.setenv("LANGUAGE", "de")
    monkeypatch.delenv("LC_CTYPE", raising=False)


def test_git_is_told_to_print_its_messages_in_english(tmp_path) -> None:
    env = sd._git_environment(tmp_path)

    assert env["LC_MESSAGES"] == "C", env
    assert "LC_ALL" not in env, env
    assert "LANGUAGE" not in env, env


def test_the_server_s_other_locale_settings_still_reach_git(tmp_path) -> None:
    """Only the messages are pinned: how git reads and writes text follows the
    server, as it did, and the ``LC_ALL`` that set it is kept as ``LC_CTYPE``."""
    env = sd._git_environment(tmp_path)

    assert env["LANG"] == "de_DE.UTF-8", env
    assert env["LC_CTYPE"] == "de_DE.UTF-8", env


def test_a_server_with_no_locale_gets_english_messages_too(
    tmp_path, monkeypatch
) -> None:
    for name in ("LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE", "LC_CTYPE"):
        monkeypatch.delenv(name, raising=False)

    env = sd._git_environment(tmp_path)

    assert env["LC_MESSAGES"] == "C", env
    assert "LC_ALL" not in env and "LC_CTYPE" not in env, env
