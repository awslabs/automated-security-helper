# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Leftover records: the daemon identity, the host key and the env-dir parents.

* A record keeps every setting a runtime client picks its daemon from, so a
  sweep under another docker config or context, podman connection or containerd
  address or namespace leaves the record alone instead of dropping it on that
  daemon's "no such container".
* The host key is absent when the PID namespace cannot be read or /proc is
  another namespace's mount, so nothing is swept on a guess.
* The env-dir parents are spelled as tempfile spells them, and a record under a
  parent that could not be listed is kept.

Nothing here starts a process or a runtime.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

from automated_security_helper.interactions import container_leftovers

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="records and directory descriptors are POSIX"
    ),
]

# Above the kernel's pid space (pid_max is at most 2**22): a stand-in for a
# creator that is gone, which no live process can hold.
_GONE_PID = 2**30 + 91


@pytest.fixture(autouse=True)
def _tempfile_reads_this_tests_tmpdir(monkeypatch):
    """The sweep searches TEMP, TMP and tempfile's own answer beside TMPDIR.

    A test here stays inside ``tmp_path`` by setting TMPDIR and emptying the
    listed parents, so the other two variables are unset and tempfile's cached
    answer is dropped for the test: a cached real temp directory would be searched
    too, and a stale private directory of this user there could be deleted by a
    test.
    """
    monkeypatch.delenv("TEMP", raising=False)
    monkeypatch.delenv("TMP", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", None)


_DAEMON_SELECTORS = (
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "CONTAINERD_ADDRESS",
    "CONTAINERD_NAMESPACE",
)


@pytest.fixture
def clean_daemon_environment(monkeypatch, tmp_path):
    for name in _DAEMON_SELECTORS:
        monkeypatch.delenv(name, raising=False)
    # A docker config directory of this test's own, holding no context.
    monkeypatch.setenv("DOCKER_CONFIG", str(tmp_path / "docker-config"))
    (tmp_path / "docker-config").mkdir()


# ---------------------------------------------------------------------------
# The daemon identity
# ---------------------------------------------------------------------------


def _record_under_the_current_daemon() -> dict:
    return {
        "runtime": "/usr/bin/docker",
        "runner_argv": [],
        "daemon_env": container_leftovers._daemon_environment(),
    }


@pytest.mark.parametrize(
    "selector",
    ["CONTAINER_CONNECTION", "CONTAINERD_ADDRESS", "CONTAINERD_NAMESPACE"],
)
def test_a_record_made_under_another_selector_is_left_alone(
    clean_daemon_environment, monkeypatch, selector
):
    record = _record_under_the_current_daemon()
    monkeypatch.setenv(selector, "another-daemon")

    assert (
        container_leftovers._differs_from_this_run(record, ["/usr/bin/docker"])
        == selector
    )


def test_a_record_made_under_another_docker_config_directory_is_left_alone(
    clean_daemon_environment, monkeypatch, tmp_path
):
    record = _record_under_the_current_daemon()
    other = tmp_path / "other-docker-config"
    other.mkdir()
    monkeypatch.setenv("DOCKER_CONFIG", str(other))

    assert (
        container_leftovers._differs_from_this_run(record, ["/usr/bin/docker"])
        == "DOCKER_CONFIG"
    )


def test_a_record_made_under_another_docker_context_file_is_left_alone(
    clean_daemon_environment, tmp_path
):
    """No variable changes: the config file's currentContext selects the daemon."""
    record = _record_under_the_current_daemon()
    (tmp_path / "docker-config" / "config.json").write_text(
        json.dumps({"currentContext": "remote-box"}), encoding="utf-8"
    )

    assert (
        container_leftovers._differs_from_this_run(record, ["/usr/bin/docker"])
        == "docker_config_current_context"
    )


def _podman_connections_file(tmp_path, monkeypatch, document) -> Path:
    config = tmp_path / "xdg-config" / "containers"
    config.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    path = config / "podman-connections.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_record_made_under_another_podman_default_connection_is_left_alone(
    clean_daemon_environment, monkeypatch, tmp_path
):
    """No variable changes: `podman system connection default` rewrites a file,
    and the sweep after it asks another machine's daemon, hears "no such
    container" and drops the record of one that is running."""
    _podman_connections_file(
        tmp_path, monkeypatch, {"Connection": {"Default": "machine-a"}}
    )
    record = _record_under_the_current_daemon()
    _podman_connections_file(
        tmp_path, monkeypatch, {"Connection": {"Default": "machine-b"}}
    )

    assert (
        container_leftovers._differs_from_this_run(record, ["/usr/bin/podman"])
        == "podman_default_connection"
    )


def test_the_older_podman_setting_in_containers_conf_is_read_too(
    clean_daemon_environment, monkeypatch, tmp_path
):
    config = tmp_path / "xdg-config" / "containers"
    config.mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    (config / "containers.conf").write_text(
        '[engine]\nactive_service = "machine-a"\n', encoding="utf-8"
    )

    assert container_leftovers._podman_default_connection() == "machine-a"


def test_the_same_podman_default_connection_differs_in_nothing(
    clean_daemon_environment, monkeypatch, tmp_path
):
    """Control."""
    _podman_connections_file(
        tmp_path, monkeypatch, {"Connection": {"Default": "machine-a"}}
    )
    record = _record_under_the_current_daemon()

    assert (
        container_leftovers._differs_from_this_run(record, ["/usr/bin/podman"]) is None
    )


def test_the_same_daemon_differs_in_nothing(clean_daemon_environment):
    """Control."""
    record = _record_under_the_current_daemon()

    assert container_leftovers._differs_from_this_run(record, ["/usr/bin/docker"]) is (
        None
    )


def test_an_older_record_without_the_new_keys_matches_an_unset_environment(
    clean_daemon_environment, monkeypatch
):
    """A record written before the keys existed is read as made under unset
    selectors: it still matches a run with none set, and differs from a run
    with one set."""
    record = {
        "runtime": "/usr/bin/docker",
        "runner_argv": [],
        "daemon_env": {
            "DOCKER_HOST": None,
            "DOCKER_CONTEXT": None,
            "CONTAINER_HOST": None,
        },
    }
    # DOCKER_CONFIG is set by the fixture, so the older record differs in it.
    assert (
        container_leftovers._differs_from_this_run(record, ["/usr/bin/docker"])
        == "DOCKER_CONFIG"
    )
    # With no selector set (the test's own home holds no docker config either,
    # so no context is selected), the keys the record never had read as unset on
    # both sides: the half that keeps a pre-upgrade record sweepable.
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    assert (
        container_leftovers._differs_from_this_run(record, ["/usr/bin/docker"]) is None
    )


def test_a_new_record_carries_every_daemon_selector(
    clean_daemon_environment, monkeypatch, tmp_path
):
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(tmp_path / "state"))
    monkeypatch.setenv("CONTAINER_CONNECTION", "podman-machine")

    path = container_leftovers.record_container(
        container_leftovers.new_container_name(), ["/usr/bin/podman"]
    )

    assert path is not None
    recorded = json.loads(path.read_text(encoding="utf-8"))["daemon_env"]
    assert set(recorded) >= set(_DAEMON_SELECTORS) | {"docker_config_current_context"}
    assert recorded["CONTAINER_CONNECTION"] == "podman-machine"


# ---------------------------------------------------------------------------
# The host key
# ---------------------------------------------------------------------------


@pytest.fixture
def boot_id(monkeypatch, tmp_path) -> Path:
    path = tmp_path / "boot_id"
    path.write_text("boot-ab12\n", encoding="ascii")
    monkeypatch.setattr(container_leftovers, "_BOOT_ID_PATH", path)
    return path


def _readlink_answering(answers):
    def readlink(path, *args, **kwargs):
        answer = answers[os.fspath(path)]
        if isinstance(answer, BaseException):
            raise answer
        return answer

    return readlink


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the Linux key")
def test_an_unreadable_pid_namespace_gives_no_host_key(boot_id, monkeypatch):
    """Not a key shared by every process whose namespace could not be read."""
    monkeypatch.setattr(
        os,
        "readlink",
        _readlink_answering(
            {
                container_leftovers._PID_NAMESPACE_LINK: OSError("unreadable"),
                container_leftovers._PROC_SELF_LINK: str(os.getpid()),
            }
        ),
    )

    assert container_leftovers._linux_scope() is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the Linux key")
def test_a_proc_of_another_pid_namespace_gives_no_host_key(boot_id, monkeypatch):
    """/proc/self names another process: the pids and start times read through
    this /proc are another namespace's, so a creator cannot be judged by them."""
    monkeypatch.setattr(
        os,
        "readlink",
        _readlink_answering(
            {
                container_leftovers._PID_NAMESPACE_LINK: "pid:[42]",
                container_leftovers._PROC_SELF_LINK: str(os.getpid() + 4242),
            }
        ),
    )

    assert container_leftovers._linux_scope() is None


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the Linux key")
def test_this_namespaces_proc_gives_the_boot_and_namespace_key(boot_id, monkeypatch):
    """Control."""
    monkeypatch.setattr(
        os,
        "readlink",
        _readlink_answering(
            {
                container_leftovers._PID_NAMESPACE_LINK: "pid:[42]",
                container_leftovers._PROC_SELF_LINK: str(os.getpid()),
            }
        ),
    )

    assert container_leftovers._linux_scope() == "linux:boot-ab12:pid:[42]"


# ---------------------------------------------------------------------------
# The env-dir parents
# ---------------------------------------------------------------------------


def test_a_tmpdir_with_a_trailing_separator_is_the_normalized_parent(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("TMPDIR", str(tmp_path) + os.sep)
    # TEMP, TMP and tempfile's cache are cleared by the module's autouse fixture,
    # so the one parent is TMPDIR's, spelled once.
    monkeypatch.setattr(container_leftovers, "_ENV_DIR_PARENTS", ())

    assert container_leftovers._env_dir_parents() == [
        os.path.normcase(os.path.abspath(str(tmp_path)))
    ]


def _env_dir_record(state: Path, directory: Path, pid: int) -> Path:
    state.mkdir(exist_ok=True, mode=0o700)
    path = state / f"ash-envdir-{directory.name}.json"
    path.write_text(
        json.dumps(
            {
                "kind": "env-dir",
                "host": container_leftovers.host_key(),
                "dir": str(directory),
                "creator_pid": pid,
                "creator_start": None,
                "created": container_leftovers._now(),
            }
        ),
        encoding="utf-8",
    )
    return path


def _private_dir(parent: Path, name: str) -> Path:
    directory = parent / name
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    (directory / "env").write_text("NAME=value\n", encoding="utf-8")
    return directory


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the host key is the Linux key"
)
def test_a_recorded_directory_under_a_tmpdir_with_a_trailing_separator_is_swept(
    monkeypatch, tmp_path
):
    """The record names the directory as tempfile spelled it (no trailing
    separator); the sweep reads TMPDIR with one. They have to meet."""
    parent = tmp_path / "tmpdir"
    parent.mkdir()
    monkeypatch.setenv("TMPDIR", str(parent) + os.sep)
    monkeypatch.setattr(container_leftovers, "_ENV_DIR_PARENTS", ())
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(tmp_path / "state"))
    if container_leftovers.host_key() is None:
        pytest.skip("this host has no key")
    stranded = _private_dir(parent, "ash-container-env-trailing01")
    record = _env_dir_record(tmp_path / "state", stranded, _GONE_PID)

    removed = container_leftovers.sweep_env_dirs()

    assert removed == [stranded.name]
    assert not stranded.exists()
    assert not record.exists()


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the host key is the Linux key"
)
def test_a_stranded_directory_under_a_symlinked_tmpdir_is_swept(monkeypatch, tmp_path):
    """TMPDIR naming a link (macOS's /tmp is one): tempfile made the directory
    through the link and the record spells it through the link. O_NOFOLLOW on
    the spelled parent refused to list it, so the directory was never swept and
    its record was dropped as "gone"; the parent is listed through its real
    path now and the record is matched by its spelling."""
    real = tmp_path / "real-tmp"
    real.mkdir()
    link = tmp_path / "linked-tmp"
    link.symlink_to(real)
    monkeypatch.setenv("TMPDIR", str(link))
    monkeypatch.setattr(container_leftovers, "_ENV_DIR_PARENTS", ())
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(tmp_path / "state"))
    if container_leftovers.host_key() is None:
        pytest.skip("this host has no key")
    stranded = _private_dir(real, "ash-container-env-linked0001")
    record = _env_dir_record(tmp_path / "state", link / stranded.name, _GONE_PID)

    removed = container_leftovers.sweep_env_dirs()

    assert removed == [stranded.name]
    assert not stranded.exists()
    assert not record.exists()


def test_a_record_under_a_parent_that_cannot_be_listed_is_kept(monkeypatch, tmp_path):
    """A parent that cannot be opened (TMPDIR naming a directory that is not
    there) says nothing about whether a record's directory is gone, so the
    record is kept; dropping it as "gone" left a directory with no record."""
    missing = tmp_path / "not-mounted-yet"
    monkeypatch.setenv("TMPDIR", str(missing))
    monkeypatch.setattr(container_leftovers, "_ENV_DIR_PARENTS", ())
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(tmp_path / "state"))
    if container_leftovers.host_key() is None:
        pytest.skip("this host has no key")
    record = _env_dir_record(
        tmp_path / "state", missing / "ash-container-env-unlisted01", _GONE_PID
    )

    removed = container_leftovers.sweep_env_dirs()

    assert removed == []
    assert record.exists(), (
        "the record was dropped although its parent could not be read"
    )


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the host key is the Linux key"
)
def test_a_record_whose_listed_parent_lacks_the_directory_is_still_dropped(
    monkeypatch, tmp_path
):
    """Control: the parent lists, the directory is gone, the creator is gone."""
    parent = tmp_path / "tmpdir"
    parent.mkdir()
    monkeypatch.setenv("TMPDIR", str(parent))
    monkeypatch.setattr(container_leftovers, "_ENV_DIR_PARENTS", ())
    monkeypatch.setenv(container_leftovers.STATE_DIR_ENV, str(tmp_path / "state"))
    if container_leftovers.host_key() is None:
        pytest.skip("this host has no key")
    record = _env_dir_record(
        tmp_path / "state", parent / "ash-container-env-gone000001", _GONE_PID
    )

    container_leftovers.sweep_env_dirs()

    assert not record.exists()
