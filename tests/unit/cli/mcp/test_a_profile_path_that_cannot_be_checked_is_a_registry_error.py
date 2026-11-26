# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``--profile`` whose path cannot be checked is refused as a registry error.

``register_profiles`` checked each profile's path (``exists``, the place it is kept,
the digest of its path) before the ``try`` that turns a load failure into a
``ProfileRegistryError``. On Python 3.10 to 3.12 ``Path.exists`` re-raises
``EACCES`` for a directory above the file that cannot be searched, so
``--profile x=/root/p.yaml`` run by a user who cannot search ``/root`` ended in a
bare ``PermissionError``, and the CLI, which reports the registry's error as a
validation error with exit 3, printed a traceback. Each of those checks now fails
as the registry's own error.
"""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

from automated_security_helper.config import session_profiles
from automated_security_helper.config.session_profiles import (
    ProfileRegistryError,
    register_profiles,
)

pytestmark = pytest.mark.unit


def test_control_a_missing_file_is_still_the_missing_file_refusal(tmp_path):
    with pytest.raises(ProfileRegistryError, match="missing file"):
        register_profiles([f"p={tmp_path / 'absent.yaml'}"])


def test_a_path_whose_exists_check_is_refused_is_a_registry_error(
    tmp_path, monkeypatch
):
    """Red at the base: ``PermissionError``."""
    real_exists = Path.exists

    def exists(self, *args, **kwargs):
        if self.name == "unsearchable.yaml":
            raise PermissionError(errno.EACCES, "Permission denied", str(self))
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", exists)

    with pytest.raises(ProfileRegistryError, match="could not be checked"):
        register_profiles([f"p={tmp_path / 'unsearchable.yaml'}"])


def test_a_check_of_the_place_a_profile_is_kept_that_raises_is_a_registry_error(
    tmp_path, monkeypatch
):
    profile = tmp_path / "p.yaml"
    profile.write_text("project_name: p\n", encoding="utf-8")

    def refused(path):
        raise RuntimeError("Symlink loop")

    monkeypatch.setattr(
        session_profiles, "_profile_kept_where_a_scan_may_rewrite_it", refused
    )

    with pytest.raises(ProfileRegistryError, match="could not be checked"):
        register_profiles([f"p={profile}"])
