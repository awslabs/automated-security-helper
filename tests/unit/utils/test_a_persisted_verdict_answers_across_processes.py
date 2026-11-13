# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A satisfied pre-installed-tool verdict answers across processes.

The in-process memo lives 600 s, so every warm run (a precommit hook per
commit) re-paid the copy's own ``--version`` probe -- seconds for checkov --
plus a uv dry run, for a copy that had not changed. A satisfied verdict is now
persisted under the user's own state directory, keyed on the copy's path,
mtime and size and on the judging uv, so a hit answers without a probe, a
changed binary misses whatever the clock says, a record past its TTL is
dropped, and nothing but "satisfied" is ever stored.
"""

from __future__ import annotations

import json
import logging
import os
import time

import pytest

from automated_security_helper.utils import pre_installed_tool as pit

pytestmark = pytest.mark.unit


@pytest.fixture
def store(tmp_path, monkeypatch):
    directory = tmp_path / "verdict-store"
    monkeypatch.setenv(pit._VERDICT_STORE_DIR_ENV, str(directory))
    pit.reset_pre_installed_tool_cache()
    yield directory
    pit.reset_pre_installed_tool_cache()


@pytest.fixture
def copy_and_uv(tmp_path):
    copy = tmp_path / "pathbin" / "checkov"
    copy.parent.mkdir()
    copy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(copy, 0o755)
    uv = tmp_path / "uv"
    uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(uv, 0o755)
    return copy, uv


def _forget_memo():
    """A new process, simulated: the in-memory memo gone, the store kept.

    Not ``reset_pre_installed_tool_cache``, which now wipes the persisted
    store too (so a test that fakes a probe, resets, and probes again gets a
    fresh probe, never the first fake's record).
    """
    with pit._verdict_cache_lock:
        pit._verdict_cache.clear()


def _counting_verify(monkeypatch, status="satisfied"):
    calls = []

    def fake_verify(
        executable, package, extras, constraint, requirement, uv_executable, values
    ):
        calls.append(1)
        return pit.PreInstalledToolVerdict(
            status,
            executable,
            requirement,
            "probed by the test double",
            version="checkov 3.2.5" if status == "satisfied" else None,
            summary="" if status == "satisfied" else "no",
        )

    monkeypatch.setattr(pit, "_verify", fake_verify)
    return calls


def _verify_once(copy, uv):
    return pit.verify_pre_installed_tool(
        str(copy),
        "checkov",
        None,
        ">=3.2.0,<4.0.0",
        uv_executable=str(uv),
        values=("hidden-value",),
    )


class _Lines(logging.Handler):
    """Collects messages: ASH_LOGGER does not propagate, so caplog misses it."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def test_a_hit_skips_the_probe_and_logs_one_line(store, copy_and_uv, monkeypatch):
    copy, uv = copy_and_uv
    calls = _counting_verify(monkeypatch)

    first = _verify_once(copy, uv)
    assert first.status == "satisfied"
    assert calls == [1]
    records = list(store.glob("*.json"))
    assert len(records) == 1
    assert (os.stat(records[0]).st_mode & 0o777) == 0o600

    # A new process: the in-memory memo is gone, the store answers.
    _forget_memo()
    from automated_security_helper.utils.log import ASH_LOGGER

    handler = _Lines()
    old_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.INFO)
    try:
        second = _verify_once(copy, uv)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(old_level)
    assert second.status == "satisfied"
    assert second.version == "checkov 3.2.5"
    assert calls == [1]
    hits = [
        message
        for message in handler.messages
        if "persisted verification verdict" in message
    ]
    assert len(hits) == 1
    # The one line names the verdict, never the requirement or the detail,
    # either of which can hold an env-read value.
    assert "satisfied" in hits[0]
    assert ">=3.2.0" not in hits[0]
    assert "hidden-value" not in hits[0]


def test_a_changed_binary_misses(store, copy_and_uv, monkeypatch):
    copy, uv = copy_and_uv
    calls = _counting_verify(monkeypatch)
    _verify_once(copy, uv)
    assert calls == [1]

    # The copy changed: a bumped mtime keys a different record.
    os.utime(copy, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
    _forget_memo()
    _verify_once(copy, uv)
    assert calls == [1, 1]


def test_a_record_past_its_ttl_is_dropped(store, copy_and_uv, monkeypatch):
    copy, uv = copy_and_uv
    calls = _counting_verify(monkeypatch)
    _verify_once(copy, uv)
    (record_path,) = store.glob("*.json")

    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["stored_at"] = time.time() - pit._PERSISTED_VERDICT_TTL_SECONDS - 60
    record_path.write_text(json.dumps(record), encoding="utf-8")

    _forget_memo()
    _verify_once(copy, uv)
    assert calls == [1, 1]


def test_a_tampered_status_is_refused_and_removed(store, copy_and_uv, monkeypatch):
    copy, uv = copy_and_uv
    calls = _counting_verify(monkeypatch)
    _verify_once(copy, uv)
    (record_path,) = store.glob("*.json")

    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["status"] = "unsatisfied"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    _forget_memo()
    verdict = _verify_once(copy, uv)
    # Re-probed, never answered from the bad record; the fresh probe's own
    # satisfied verdict is persisted again under the same key.
    assert verdict.status == "satisfied"
    assert calls == [1, 1]
    rewritten = json.loads(record_path.read_text(encoding="utf-8"))
    assert rewritten["status"] == "satisfied"


def test_only_satisfied_verdicts_are_persisted(store, copy_and_uv, monkeypatch):
    copy, uv = copy_and_uv
    calls = _counting_verify(monkeypatch, status="unsatisfied")
    verdict = _verify_once(copy, uv)
    assert verdict.status == "unsatisfied"
    assert calls == [1]
    assert list(store.glob("*.json")) == []


def test_persistence_off_still_verifies(copy_and_uv, monkeypatch):
    copy, uv = copy_and_uv
    monkeypatch.setenv(pit._VERDICT_STORE_DIR_ENV, "off")
    pit.reset_pre_installed_tool_cache()
    calls = _counting_verify(monkeypatch)
    assert _verify_once(copy, uv).status == "satisfied"
    pit.reset_pre_installed_tool_cache()
    assert _verify_once(copy, uv).status == "satisfied"
    assert calls == [1, 1]


def test_the_reset_forgets_the_store_too(store, copy_and_uv, monkeypatch):
    """A reset means re-probe: the store must not answer from behind it."""
    copy, uv = copy_and_uv
    calls = _counting_verify(monkeypatch)
    _verify_once(copy, uv)
    assert len(list(store.glob("*.json"))) == 1

    pit.reset_pre_installed_tool_cache()
    assert list(store.glob("*.json")) == []
    _verify_once(copy, uv)
    assert calls == [1, 1]


def _venv_shaped_copy(tmp_path, system_site=False):
    """A console script whose shebang names an isolated venv's python."""
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    interpreter = venv / "bin" / "python"
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(interpreter, 0o755)
    (venv / "pyvenv.cfg").write_text(
        "home = /usr/bin\n"
        f"include-system-site-packages = {'true' if system_site else 'false'}\n"
        "version = 3.12.15\n",
        encoding="utf-8",
    )
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    copy = tmp_path / "venvbin" / "checkov"
    copy.parent.mkdir()
    copy.write_text(f"#!{interpreter}\nraise SystemExit(0)\n", encoding="utf-8")
    os.chmod(copy, 0o755)
    return copy, site


def test_a_changed_environment_misses(store, copy_and_uv, monkeypatch, tmp_path):
    """The record pins the ENVIRONMENT the judge verified, not just the launcher.

    A `pip uninstall` or downgrade rewrites no console script, but it adds or
    removes entries under site-packages, which moves that directory's mtime --
    and the record's key carries it, so the stale "satisfied" misses.
    """
    _, uv = copy_and_uv
    copy, site = _venv_shaped_copy(tmp_path)
    calls = _counting_verify(monkeypatch)

    _verify_once(copy, uv)
    (record_path,) = store.glob("*.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    # A pinned environment gets the full TTL.
    assert record["ttl_seconds"] == pit._PERSISTED_VERDICT_TTL_SECONDS

    _forget_memo()
    _verify_once(copy, uv)
    assert calls == [1]

    # The environment changed under the unchanged launcher: a distribution
    # removed from site-packages moves the directory's mtime.
    os.utime(site, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
    _forget_memo()
    _verify_once(copy, uv)
    assert calls == [1, 1]


def test_a_system_site_venv_is_not_pinned(store, copy_and_uv, monkeypatch, tmp_path):
    """include-system-site-packages re-opens directories the stamp never reads."""
    _, uv = copy_and_uv
    copy, _ = _venv_shaped_copy(tmp_path, system_site=True)
    _counting_verify(monkeypatch)
    _verify_once(copy, uv)
    (record_path,) = store.glob("*.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["ttl_seconds"] == pit._UNPINNED_VERDICT_TTL_SECONDS


def test_an_unpinnable_environment_gets_the_short_ttl(store, copy_and_uv, monkeypatch):
    """A copy whose environment cannot be read answers only briefly from disk."""
    copy, uv = copy_and_uv  # a /bin/sh script: no Python environment to pin
    calls = _counting_verify(monkeypatch)
    _verify_once(copy, uv)
    (record_path,) = store.glob("*.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["ttl_seconds"] == pit._UNPINNED_VERDICT_TTL_SECONDS

    # Past the short TTL the record is dropped, well inside the full one.
    record["stored_at"] = time.time() - pit._UNPINNED_VERDICT_TTL_SECONDS - 60
    record_path.write_text(json.dumps(record), encoding="utf-8")
    _forget_memo()
    _verify_once(copy, uv)
    assert calls == [1, 1]
