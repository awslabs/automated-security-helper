# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The express runtime directory is private, policed, and refused when it cannot be.

The socket there is credential-equivalent -- anything that can connect to it
runs scans as this user -- so the directory it lives in is 0700, owned by the
invoking user, never reached through a symlink, and everything short of that
is a :class:`ExpressUnavailable` refusal, which the client reads as "run cold".

Filesystem-only: no sockets are opened here (that is the integration tier's
job), and nothing in this file needs express to be supported on the host beyond
posix path semantics, so the whole module skips where the platform has none.
"""

import os
import stat
from pathlib import Path

import pytest

from automated_security_helper.express import runtime

pytestmark = pytest.mark.unit

needs_posix = pytest.mark.skipif(
    not runtime.express_supported(), reason="express mode is unix-only"
)


@needs_posix
class TestRuntimeDir:
    def test_xdg_runtime_dir_gets_a_private_subdirectory(self, tmp_path):
        made = runtime.runtime_dir({"XDG_RUNTIME_DIR": str(tmp_path)})
        assert made == tmp_path / "ash-express"
        assert stat.S_IMODE(os.lstat(made).st_mode) == 0o700

    def test_without_xdg_the_home_run_directory_is_used(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        made = runtime.runtime_dir({})
        assert made == tmp_path / ".ash" / "run"
        assert stat.S_IMODE(os.lstat(made).st_mode) == 0o700

    def test_an_xdg_value_that_is_not_a_directory_falls_back_to_home(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        made = runtime.runtime_dir({"XDG_RUNTIME_DIR": str(tmp_path / "absent")})
        assert made == tmp_path / ".ash" / "run"

    def test_a_loose_mode_on_an_owned_directory_is_corrected(self, tmp_path):
        target = tmp_path / "ash-express"
        target.mkdir(mode=0o755)
        os.chmod(target, 0o755)
        runtime.runtime_dir({"XDG_RUNTIME_DIR": str(tmp_path)})
        assert stat.S_IMODE(os.lstat(target).st_mode) == 0o700

    def test_a_symlinked_directory_is_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        (tmp_path / "ash-express").symlink_to(real)
        with pytest.raises(runtime.ExpressUnavailable, match="without\\s+following"):
            runtime.runtime_dir({"XDG_RUNTIME_DIR": str(tmp_path)})

    def test_a_directory_owned_by_another_user_is_refused(self, tmp_path, monkeypatch):
        (tmp_path / "ash-express").mkdir(mode=0o700)
        # The test cannot chown, so the check's idea of "this user" moves instead:
        # the directory really is owned by someone other than the uid compared.
        # The real uid is read before the patch; a lambda that asked os.getuid
        # again would be asking itself.
        real_uid = os.getuid()
        monkeypatch.setattr(os, "getuid", lambda: real_uid + 1)
        with pytest.raises(runtime.ExpressUnavailable, match="owned by uid"):
            runtime.runtime_dir({"XDG_RUNTIME_DIR": str(tmp_path)})

    def test_socket_and_log_names_carry_the_uid_and_the_version_key(self, tmp_path):
        environ = {"XDG_RUNTIME_DIR": str(tmp_path)}
        sock = runtime.socket_path(environ)
        log = runtime.log_path(environ)
        key = runtime.socket_key()
        assert sock.name == f"ash-{os.getuid()}-{key}.sock"
        assert log.name == f"ash-{os.getuid()}-{key}.log"
        assert sock.parent == tmp_path / "ash-express"

    def test_the_socket_key_moves_with_the_version_and_the_uid(self):
        base = runtime.socket_key(version="1.0.0", uid=1000)
        assert runtime.socket_key(version="1.0.1", uid=1000) != base
        assert runtime.socket_key(version="1.0.0", uid=1001) != base
        assert runtime.socket_key(version="1.0.0", uid=1000) == base


@needs_posix
class TestIdleSetting:
    def test_the_default_stands_without_the_variable(self):
        assert runtime.idle_seconds({}) == runtime.DEFAULT_IDLE_SECONDS

    @pytest.mark.parametrize("raw", ["", "soon", "-5", "0", "1.5"])
    def test_an_unusable_value_is_ignored_not_fatal(self, raw):
        assert (
            runtime.idle_seconds({runtime.IDLE_ENV: raw})
            == runtime.DEFAULT_IDLE_SECONDS
        )

    def test_a_positive_integer_is_taken(self):
        assert runtime.idle_seconds({runtime.IDLE_ENV: "120"}) == 120
