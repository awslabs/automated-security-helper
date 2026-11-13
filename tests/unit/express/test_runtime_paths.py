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
        os.chmod(target, 0o755)  # nosec B103 - the loose mode is the fixture under test
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

    def test_socket_and_log_names_carry_the_uid_and_the_version_key(self):
        # A short directory of this test's own: pytest's tmp_path can be long
        # enough to trip the AF_UNIX length refusal this module enforces.
        import shutil
        import tempfile

        base = tempfile.mkdtemp(prefix="ash-t", dir="/tmp")  # nosec B108 - mkdtemp makes a private 0700 dir; the fixed parent keeps the socket path under the AF_UNIX cap
        try:
            environ = {"XDG_RUNTIME_DIR": base}
            sock = runtime.socket_path(environ)
            log = runtime.log_path(environ)
            key = runtime.socket_key()
            assert sock.name == f"ash-{os.getuid()}-{key}.sock"
            assert log.name == f"ash-{os.getuid()}-{key}.log"
            assert sock.parent == Path(base) / "ash-express"
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def test_a_socket_path_over_the_af_unix_limit_is_refused(self, tmp_path):
        """bind() on an over-long AF_UNIX path fails only after the daemon has
        already forked, so the length is refused up front and the scan runs
        cold instead of spending a start window on every invocation."""
        padding = max(8, runtime.MAX_SOCKET_PATH_BYTES - len(str(tmp_path)) + 8)
        deep = tmp_path / ("x" * padding)
        deep.mkdir()
        with pytest.raises(runtime.ExpressUnavailable, match="AF_UNIX"):
            runtime.socket_path({"XDG_RUNTIME_DIR": str(deep)})

    def test_the_socket_key_moves_with_the_version_the_uid_and_the_prefix(self):
        base = runtime.socket_key(version="1.0.0", uid=1000, prefix="/venv/a")
        assert runtime.socket_key(version="1.0.1", uid=1000, prefix="/venv/a") != base
        assert runtime.socket_key(version="1.0.0", uid=1001, prefix="/venv/a") != base
        # Two installations of one version never share a socket: without this,
        # each --express run would stop and restart the other's daemon forever.
        assert runtime.socket_key(version="1.0.0", uid=1000, prefix="/venv/b") != base
        assert runtime.socket_key(version="1.0.0", uid=1000, prefix="/venv/a") == base


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


class TestFingerprintCoversInterpreterShaping:
    """``sys.path`` is left out of the fingerprint on purpose, so the entries
    PYTHONPATH adds are covered by hashing the variable itself: a client whose
    value differs from the daemon's must read it as stale."""

    @pytest.mark.parametrize("name", runtime.FINGERPRINT_ENV)
    def test_a_changed_value_changes_the_fingerprint(self, monkeypatch, name):
        monkeypatch.delenv(name, raising=False)
        unset = runtime.runtime_fingerprint()
        monkeypatch.setenv(name, "/work/one")
        one = runtime.runtime_fingerprint()
        monkeypatch.setenv(name, "/work/two")
        two = runtime.runtime_fingerprint()
        assert len({unset, one, two}) == 3

    def test_the_same_values_give_the_same_fingerprint(self, monkeypatch):
        monkeypatch.setenv("PYTHONPATH", "/work/one")
        assert runtime.runtime_fingerprint() == runtime.runtime_fingerprint()

    def test_an_unrelated_variable_does_not_move_it(self, monkeypatch):
        before = runtime.runtime_fingerprint()
        monkeypatch.setenv("ASH_SOMETHING_ELSE", "x")
        monkeypatch.setenv("AWS_PROFILE", "other")
        assert runtime.runtime_fingerprint() == before

    def test_the_no_user_site_flag_is_hashed(self, monkeypatch):
        import sys
        import types

        before = runtime.runtime_fingerprint()
        flags = types.SimpleNamespace(no_user_site=1 - sys.flags.no_user_site)
        monkeypatch.setattr(runtime.sys, "flags", flags)
        assert runtime.runtime_fingerprint() != before

    def test_the_daemon_scrub_keeps_what_the_fingerprint_hashes(self):
        """The daemon computes its fingerprint from its own scrubbed
        environment, so every hashed variable must survive the scrub or a
        client with PYTHONPATH set would read every daemon as stale."""
        environ = dict.fromkeys(runtime.FINGERPRINT_ENV, "/x")
        assert runtime.scrubbed_daemon_environment(environ) == environ
        assert set(runtime.FINGERPRINT_ENV) <= set(runtime.INTERPRETER_ENV)
