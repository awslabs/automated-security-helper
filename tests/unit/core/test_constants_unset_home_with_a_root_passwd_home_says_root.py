# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unset HOME whose passwd home is ``/`` is reported as a root, not as no home.

Why these tests exist
---------------------
With HOME unset the home comes from the passwd entry. Since a home that is the
filesystem root is refused, an entry of ``/`` (RHEL's ``nobody`` has one) gives no
usable home. The warning said "the passwd entry names no absolute home directory"
for it, though ``/`` is absolute, and its advice did not say that the root is what
is refused. It now says the entry's home is the filesystem root and asks for a path
other than it. An entry that is empty or relative keeps the old wording.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import constants
from automated_security_helper.core.constants import warn_if_home_unusable

pytestmark = pytest.mark.unit

posix_only = pytest.mark.skipif(os.name == "nt", reason="HOME is not Windows' home")


@pytest.fixture
def logger(monkeypatch):
    monkeypatch.setattr(constants, "_warned_relative_values", set())
    from automated_security_helper.utils import log as ash_log

    recorder = MagicMock()
    monkeypatch.setattr(ash_log, "ASH_LOGGER", recorder)
    return recorder


def _passwd_home(monkeypatch, home: str) -> None:
    import pwd

    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.setattr(
        pwd, "getpwuid", lambda uid: SimpleNamespace(pw_dir=home), raising=True
    )


@posix_only
def test_a_root_passwd_home_is_named_as_the_filesystem_root(monkeypatch, logger):
    _passwd_home(monkeypatch, "/")

    warn_if_home_unusable()

    message = logger.warning.call_args.args[0]
    # Red at the base: "the passwd entry names no absolute home directory".
    assert "the passwd entry's home directory is the filesystem root" in message
    assert "names no absolute home directory" not in message
    assert "Set HOME to an absolute path other than the filesystem root." in message


@posix_only
@pytest.mark.parametrize("home", ["", "relative/home"])
def test_a_passwd_home_that_is_not_absolute_keeps_the_old_wording(
    monkeypatch, logger, home
):
    """The control: only a root gets the new reason."""
    _passwd_home(monkeypatch, home)

    warn_if_home_unusable()

    message = logger.warning.call_args.args[0]
    assert "the passwd entry names no absolute home directory" in message
    assert "other than the filesystem root" not in message


@posix_only
def test_a_usable_passwd_home_warns_about_nothing(monkeypatch, logger, tmp_path):
    _passwd_home(monkeypatch, str(tmp_path))

    warn_if_home_unusable()

    logger.warning.assert_not_called()
