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

    def test_home_comes_from_the_given_environment_not_the_process(
        self, tmp_path, monkeypatch
    ):
        """A caller that passes an explicit environment controls the whole
        result: Path.home() is only the answer when the mapping has no HOME."""
        monkeypatch.setattr(
            Path, "home", lambda: pytest.fail("the mapping's HOME must win")
        )
        made = runtime.runtime_dir({"HOME": str(tmp_path)})
        assert made == tmp_path / ".ash" / "run"

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

    def test_without_a_mapping_the_process_environment_is_read_by_the_constant(
        self, monkeypatch
    ):
        monkeypatch.setenv(runtime.IDLE_ENV, "77")
        assert runtime.idle_seconds() == 77
        monkeypatch.delenv(runtime.IDLE_ENV)
        assert runtime.idle_seconds() == runtime.DEFAULT_IDLE_SECONDS


class TestOwnTreeStamp:
    """The source-tree walk pays only where it buys something: an editable
    install or a checkout, whose code changes with no dist-info change. A
    package inside a site directory is fixed by its dist-info, which the
    fingerprint already hashes."""

    def test_a_package_inside_a_site_directory_is_not_walked(self, monkeypatch):
        # runtime.py lives in <parent>/automated_security_helper/express/.
        package_parent = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(runtime.__file__)))
        )
        monkeypatch.setattr(runtime, "_site_directories", lambda: [package_parent])
        monkeypatch.setattr(
            os, "walk", lambda *_a, **_k: pytest.fail("a regular install is not walked")
        )
        assert runtime._own_tree_stamp() == "installed"

    def test_a_package_outside_every_site_directory_is_walked(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(runtime, "_site_directories", lambda: [str(tmp_path)])
        count, _, newest = runtime._own_tree_stamp().partition(":")
        assert int(count) > 50 and int(newest) > 0

    def test_an_edit_to_an_editable_tree_changes_the_stamp(self, monkeypatch):
        """The stamp moves with the newest mtime of the package's modules, so
        an edit-scan loop sees its edit."""
        import types

        monkeypatch.setattr(runtime, "_site_directories", list)
        mtimes = {"a.py": 100, "b.py": 200}
        real_stat = os.stat

        def stat(path, *args, **kwargs):
            # Only the modules the fake walk names are faked; pytest's own
            # files keep their real stat.
            name = os.path.basename(path)
            if name in mtimes:
                return types.SimpleNamespace(st_mtime_ns=mtimes[name])
            return real_stat(path, *args, **kwargs)

        with monkeypatch.context() as patched:
            patched.setattr(
                os, "walk", lambda root: [(root, [], ["a.py", "b.py", "data.json"])]
            )
            patched.setattr(os, "stat", stat)
            assert runtime._own_tree_stamp() == "2:200"
            mtimes["a.py"] = 300  # an edit
            assert runtime._own_tree_stamp() == "2:300"


class TestSocketKeyCarriesTheInterpreterShape:
    """Two shells that differ only in PYTHONPATH import different plugin code,
    so each gets a daemon of its own. Keyed into the fingerprint instead, each
    would read the other's daemon as stale and, under --express, stop it and its
    in-flight scans, forever. The key is 16 hex characters either way, so the
    socket path's length is unchanged."""

    @pytest.mark.parametrize(
        "name",
        [
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONUSERBASE",
            "PYTHONNOUSERSITE",
            "VIRTUAL_ENV",
        ],
    )
    def test_a_changed_value_changes_the_key(self, monkeypatch, name):
        monkeypatch.delenv(name, raising=False)
        unset = runtime.socket_key(version="1", uid=1, prefix="/p")
        monkeypatch.setenv(name, "/work/one")
        one = runtime.socket_key(version="1", uid=1, prefix="/p")
        monkeypatch.setenv(name, "/work/two")
        two = runtime.socket_key(version="1", uid=1, prefix="/p")
        assert len({unset, one, two}) == 3
        assert len(one) == 16

    def test_two_shells_with_different_pythonpaths_reach_different_daemons_and_neither_is_stale(
        self, monkeypatch
    ):
        monkeypatch.setenv("PYTHONPATH", "/work/hook")
        hook = runtime.socket_key(version="1", uid=1, prefix="/p")
        hook_fingerprint = runtime.runtime_fingerprint()
        monkeypatch.setenv("PYTHONPATH", "/work/ide")
        ide = runtime.socket_key(version="1", uid=1, prefix="/p")
        # Different daemons (different sockets, so no restart of each other)...
        assert hook != ide
        assert len(hook) == len(ide) == 16, "the socket path's length is unchanged"
        # ...and the fingerprint is the same for both, so a daemon never reads
        # a request from the other shape as stale.
        assert runtime.runtime_fingerprint() == hook_fingerprint

    def test_an_unrelated_variable_does_not_move_the_key(self, monkeypatch):
        before = runtime.socket_key(version="1", uid=1, prefix="/p")
        monkeypatch.setenv("AWS_PROFILE", "other")
        assert runtime.socket_key(version="1", uid=1, prefix="/p") == before

    def test_a_relative_entry_is_made_absolute_against_the_callers_directory(
        self, tmp_path, monkeypatch
    ):
        """PYTHONPATH=. names one tree per working directory; the daemon starts
        in the runtime directory, so the client resolves it first. Two
        directories give two keys, and the scrub hands the daemon the absolute
        spelling, from which it computes the key its client expects."""
        one, two = tmp_path / "one", tmp_path / "two"
        one.mkdir()
        two.mkdir()
        monkeypatch.setenv("PYTHONPATH", ".")
        monkeypatch.chdir(one)
        key_one = runtime.socket_key(version="1", uid=1, prefix="/p")
        scrubbed = runtime.scrubbed_daemon_environment({"PYTHONPATH": "."})
        assert os.path.isabs(scrubbed["PYTHONPATH"])
        assert os.path.samefile(scrubbed["PYTHONPATH"], one)
        monkeypatch.chdir(two)
        assert runtime.socket_key(version="1", uid=1, prefix="/p") != key_one
        # The daemon, started elsewhere with the absolute value, agrees with
        # the client that started it from `one`.
        daemon_environ = {"PYTHONPATH": scrubbed["PYTHONPATH"]}
        monkeypatch.chdir(tmp_path)
        assert runtime.interpreter_shape(daemon_environ) == (
            "\x00".join((scrubbed["PYTHONPATH"], "", "", "", ""))
        )

    def test_the_daemon_scrub_keeps_every_variable_the_key_reads(self):
        environ = dict.fromkeys(runtime.INTERPRETER_ENV, "/x")
        assert runtime.scrubbed_daemon_environment(environ) == environ
