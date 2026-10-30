# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner inventory's probe, entry and lock bounds, as the low findings read them.

What each test pins, and what it read at the base before the fix:

* the fallback version probe runs in the throwaway probe directory (it ran in
  the process's working directory);
* the probe's stdout and stderr are joined on a line break ("1.2" and
  "3 warnings" fused into 1.23);
* a scanner class whose ``offline_strategy`` is not an enum, or whose config
  read raises, is described with what is knowable (``.value`` raised outside
  any try and failed the whole inventory), and one whose description raises
  anyway is listed as a placeholder (it aborted the whole list);
* a constructed scanner with config None is still read against the operator's
  configuration (it kept ``enabled: True`` whatever the operator switched off);
* an unvalidated section's ``enabled`` spelled ``"false"`` reads as False (it
  was reported as the string, which every truthiness reader read as enabled);
* a scanner that runs its tool through uv (``use_uv_tool``) gets no PATH
  fallback probe (the version of whichever same-named binary was first on PATH
  was reported), and one that does not run through uv is probed (a later cut
  gated on the uv mixin's method, which every plugin has, and probed nothing);
* the inventory lock is taken with a bound (it was taken forever);
* a caller's configuration is the one the probes run under (the default
  configuration of the tree was always used).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core import scanner_inventory
from automated_security_helper.core.scanner_inventory import (
    _probe_tool_version,
    describe_scanner,
    list_scanner_inventory,
)

pytestmark = pytest.mark.unit


class _NoSection:
    def get_plugin_config(self, plugin_type, plugin_name):
        return None


class _DictSection:
    def __init__(self, section):
        self._section = section

    def get_plugin_config(self, plugin_type, plugin_name):
        return self._section


class _ModelSection:
    def __init__(self, enabled):
        self.enabled = enabled


class _OperatorSays:
    def __init__(self, enabled):
        self._enabled = enabled

    def get_plugin_config(self, plugin_type, plugin_name):
        return _ModelSection(self._enabled)


def _probe_run(monkeypatch, stdout="", stderr="", returncode=0):
    """Route the probe's run_command to a fake and record its calls."""
    from automated_security_helper.utils import subprocess_utils

    calls = []

    def run_command(args, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(subprocess_utils, "run_command", run_command)
    monkeypatch.setattr(
        subprocess_utils, "find_executable", lambda command: f"/usr/bin/{command}"
    )
    monkeypatch.setattr(subprocess_utils, "run_succeeded", lambda result: True)
    return calls


# ---------------------------------------------------------------------------
# The version probe
# ---------------------------------------------------------------------------


def test_the_probe_runs_in_the_directory_it_is_given(monkeypatch, tmp_path):
    """Red before the fix: no cwd reached run_command, so the tool ran where the
    process did."""
    calls = _probe_run(monkeypatch, stdout="grype 0.79.0\n")

    assert _probe_tool_version("grype", cwd=tmp_path) == "0.79.0"
    assert calls and calls[0]["cwd"] == tmp_path


def test_stdout_and_stderr_are_joined_on_a_line_break(monkeypatch):
    """Red before the fix: "syft 1.2" + "3 warnings" read as 1.23."""
    _probe_run(monkeypatch, stdout="syft 1.2", stderr="3 warnings were printed")

    assert _probe_tool_version("syft") == "1.2"


# ---------------------------------------------------------------------------
# describe_scanner survives one odd class
# ---------------------------------------------------------------------------


class _PlainTextStrategy:
    """A scanner whose offline_strategy is text, not an enum, and whose config
    read raises."""

    offline_strategy = "no_network"

    def __init__(self, context=None):
        pass

    @property
    def config(self):
        raise RuntimeError("config is not readable")

    def validate_plugin_dependencies(self):
        return True


def test_a_non_enum_offline_strategy_and_a_raising_config_are_described(monkeypatch):
    """Red before the fix: AttributeError on str.value before any try."""
    monkeypatch.setattr(scanner_inventory, "_probe_tool_version", lambda *a, **k: None)

    entry = describe_scanner(
        _PlainTextStrategy, context=object(), default_config=_NoSection()
    )

    assert entry["name"] == "_plain_text_strategy"
    assert entry["offline_strategy"] == "no_network"
    assert entry["dependencies_satisfied"] is True


def test_one_scanner_whose_description_raises_is_a_placeholder(monkeypatch):
    """Red before the fix: the exception aborted list_scanner_inventory and no
    scanner at all was listed."""

    class _Fine:
        offline_strategy = None

        def __init__(self, context=None):
            self.config = None

        def validate_plugin_dependencies(self):
            return False

    class _Broken:
        offline_strategy = None

        def __init__(self, context=None):
            self.config = None

    def describe(cls, context, default_config):
        if cls is _Broken:
            raise RuntimeError("cannot describe")
        return {"name": "fine", "version": None}

    monkeypatch.setattr(scanner_inventory, "describe_scanner", describe)
    monkeypatch.setattr(scanner_inventory, "_INVENTORY_LOCK_WAIT_SECONDS", 5.0)

    listed = list_scanner_inventory(lambda: [_Fine, _Broken])

    assert [entry["name"] for entry in listed] == ["fine", "_broken"]
    assert listed[1]["enabled"] is None
    assert listed[1]["dependencies_satisfied"] is None


# ---------------------------------------------------------------------------
# The enabled flag
# ---------------------------------------------------------------------------


class _ConfigLess:
    offline_strategy = None

    def __init__(self, context=None):
        self.config = None

    def validate_plugin_dependencies(self):
        return False


def test_a_scanner_with_no_config_still_honors_the_operators_switch(monkeypatch):
    """Red before the fix: the operator lookup ran only when config was not
    None, so the entry kept enabled True."""
    entry = describe_scanner(
        _ConfigLess, context=object(), default_config=_OperatorSays(enabled=False)
    )

    assert entry["enabled"] is False


def test_an_unvalidated_sections_textual_false_reads_as_false():
    """Red before the fix: the raw string "false" was reported, which is truthy."""
    entry = describe_scanner(
        _ConfigLess,
        context=object(),
        default_config=_DictSection({"enabled": "false"}),
    )

    assert entry["enabled"] is False


def test_an_unvalidated_sections_other_text_is_kept_as_written():
    """Control: a value that spells no boolean is still shown as written."""
    entry = describe_scanner(
        _ConfigLess,
        context=object(),
        default_config=_DictSection({"enabled": "sometimes"}),
    )

    assert entry["enabled"] == "sometimes"


# ---------------------------------------------------------------------------
# No PATH probe for a uv-run tool
# ---------------------------------------------------------------------------


class _PathTool:
    """A scanner that runs the binary on PATH: no uv, no self-reported version.

    Every plugin inherits ``resolve_deferred_tool_version`` from the uv mixin,
    so the stand-in defines it too: the inventory must tell a uv-run tool apart
    by the ``use_uv_tool`` flag, never by that method's presence.
    """

    offline_strategy = None
    command = "grype"
    use_uv_tool = False

    def __init__(self, context=None):
        self.config = None
        self.tool_version = None

    def validate_plugin_dependencies(self):
        return True

    def resolve_deferred_tool_version(self):
        return None


class _UvRun(_PathTool):
    """A scanner that runs its tool through uv, as bandit does (use_uv_tool)."""

    command = "bandit"
    use_uv_tool = True


def _recording_probe(monkeypatch):
    probed = []
    monkeypatch.setattr(
        scanner_inventory,
        "_probe_tool_version",
        lambda command, **kwargs: probed.append(command) or "9.9.9",
    )
    return probed


def test_a_uv_run_tool_is_not_probed_on_path(monkeypatch):
    """Red before the fix: version None with dependencies True probed the
    first same-named binary on PATH. The stand-in marks itself a uv-run tool
    the way the product's scanners do, with ``use_uv_tool``; an earlier cut of
    this pin marked it by the mixin method alone, which every plugin has, and
    so pinned a gate that excluded every scanner."""
    probed = _recording_probe(monkeypatch)

    entry = describe_scanner(_UvRun, context=object(), default_config=_NoSection())

    assert probed == []
    assert entry["version"] is None


def test_a_path_tool_without_a_version_is_probed(monkeypatch):
    """The other arm of the gate: a scanner that does not run through uv, is
    reachable and reports no version of its own is asked its version on PATH.
    Red on the cut whose gate tested for the mixin method: nothing was probed."""
    probed = _recording_probe(monkeypatch)

    entry = describe_scanner(_PathTool, context=object(), default_config=_NoSection())

    assert probed == ["grype"]
    assert entry["version"] == "9.9.9"


# ---------------------------------------------------------------------------
# The inventory lock
# ---------------------------------------------------------------------------


class _RecordingLock:
    def __init__(self, admit=True):
        self.admit = admit
        self.timeouts = []
        self.released = 0

    def acquire(self, blocking=True, timeout=-1):
        self.timeouts.append(timeout)
        return self.admit

    def release(self):
        self.released += 1

    def __enter__(self):
        self.timeouts.append(None)
        return self

    def __exit__(self, *exc):
        self.released += 1
        return False


def test_the_inventory_lock_is_taken_with_a_bound(monkeypatch):
    """Red before the fix: the lock was entered with no timeout at all."""
    lock = _RecordingLock()
    monkeypatch.setattr(scanner_inventory, "_INVENTORY_LOCK", lock)

    list_scanner_inventory(list)

    assert lock.timeouts and lock.timeouts[0] is not None
    assert lock.timeouts[0] > 0
    assert lock.released == 1


def test_a_lock_held_past_the_bound_refuses_instead_of_waiting(monkeypatch):
    """Red before the fix: nothing could refuse; the caller waited forever."""
    monkeypatch.setattr(
        scanner_inventory, "_INVENTORY_LOCK", _RecordingLock(admit=False)
    )

    with pytest.raises(TimeoutError, match="inventory lock"):
        list_scanner_inventory(list)


# ---------------------------------------------------------------------------
# The configuration the probes run under
# ---------------------------------------------------------------------------


def test_a_given_configuration_is_the_one_the_probes_run_under(monkeypatch):
    """Red before the fix: list_scanner_inventory took no config and built the
    probe context with AshConfig()."""
    from automated_security_helper.config.ash_config import AshConfig

    seen = {}

    class _Recording:
        offline_strategy = None

        def __init__(self, context=None):
            seen["context_config"] = context.config
            self.config = None

        def validate_plugin_dependencies(self):
            return False

    config = AshConfig(project_name="given-to-the-inventory")
    monkeypatch.setattr(scanner_inventory, "_INVENTORY_LOCK_WAIT_SECONDS", 5.0)

    list_scanner_inventory(lambda: [_Recording], config=config)

    assert seen["context_config"] is config


def test_describe_scanner_reads_the_probe_directory_from_the_context(monkeypatch):
    """The probe is handed the context's source directory, the throwaway one."""
    seen = {}

    class _Reachable:
        offline_strategy = None
        command = "grype"

        def __init__(self, context=None):
            self.config = None
            self.tool_version = None

        def validate_plugin_dependencies(self):
            return True

    def probe(command, cwd=None):
        seen["cwd"] = cwd
        return "0.1.0"

    monkeypatch.setattr(scanner_inventory, "_probe_tool_version", probe)
    context = MagicMock()
    context.source_dir = Path("/probe/source")

    entry = describe_scanner(_Reachable, context=context, default_config=_NoSection())

    assert entry["version"] == "0.1.0"
    assert seen["cwd"] == Path("/probe/source")
