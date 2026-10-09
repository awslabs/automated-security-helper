# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""firejail is refused when it would run a scanner without confining it.

Inside a container that has its own PID namespace, firejail finds no kernel threads
among PIDs 1-10, decides it is already inside a sandbox, and runs the command with
none of its options. The command still exits 0, and --quiet hides the one warning
firejail prints, so a probe that only checked the exit status passed. The probe now
runs a command that prints its mount namespace and compares it with ASH's.

These tests stand in for firejail with a fake ``subprocess.run`` and give ASH a fixed
mount namespace, so they run on every platform. The real firejail is exercised by
tests/integration/sandbox/test_firejail_probe.py.
"""

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.utils.sandbox import (
    SandboxRequirements,
    SandboxUnavailable,
    clear_backend_cache,
    resolve_backend,
    scanner_sandbox_scope,
)
from automated_security_helper.utils.sandbox import backends
from automated_security_helper.utils.sandbox.backends import (
    BwrapBackend,
    FirejailBackend,
    LandlockBackend,
)

ASH_NAMESPACE = "mnt:[4026531841]"
SANDBOX_NAMESPACE = "mnt:[4026532917]"
#: What firejail 0.9.72 prints (src/firejail/no_sandbox.c) unless --quiet.
EXISTING_SANDBOX_WARNING = (
    "Warning: an existing sandbox was detected. /usr/bin/readlink will run without "
    "any additional sandboxing features"
)
UNCONFINED = "without a sandbox"


class FakeFirejail:
    """Answers every ``subprocess.run`` call the way a firejail would."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.calls: List[List[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(
            list(argv), self.returncode, self.stdout, self.stderr
        )


def unconfined() -> FakeFirejail:
    """A firejail that ran the command in ASH's own mount namespace, quietly."""
    return FakeFirejail(stdout=ASH_NAMESPACE + "\n")


def confined() -> FakeFirejail:
    """A firejail that built a sandbox, with the banner it prints without --quiet."""
    return FakeFirejail(
        stdout=(
            "Parent pid 4100, child pid 4101\n"
            "Child process initialized in 9.12 ms\n"
            f"{SANDBOX_NAMESPACE}\n"
            "\nParent is shutting down, bye...\n"
        )
    )


@pytest.fixture
def linux_host(monkeypatch):
    """A Linux machine with firejail installed, whose mount namespace is ASH_NAMESPACE.

    Returns a function that installs the firejail every probe run talks to.
    """
    monkeypatch.setattr(backends.platform, "system", lambda: "Linux")
    real_which = shutil.which

    def which(name, *args, **kwargs):
        if name in ("firejail", "readlink"):
            return f"/usr/bin/{name}"
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(backends.shutil, "which", which)
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if os.fspath(path) == "/proc/self/ns/mnt":
            return ASH_NAMESPACE
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(backends.os, "readlink", readlink)

    def install(fake: FakeFirejail) -> FakeFirejail:
        monkeypatch.setattr(backends.subprocess, "run", fake)
        return fake

    clear_backend_cache()
    yield install
    clear_backend_cache()


def _context(tmp_path, mode):
    return SimpleNamespace(
        config=AshConfig(sandbox=SandboxConfig(mode=mode)),
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
    )


def _plugin():
    return SimpleNamespace(
        config=SimpleNamespace(name="grype"),
        sandbox_requirements=SandboxRequirements(),
        results_dir=None,
    )


class TestFirejailProbe:
    def test_a_command_left_in_ashs_mount_namespace_makes_firejail_unavailable(
        self, linux_host
    ):
        linux_host(unconfined())
        reason = FirejailBackend().probe()
        assert reason is not None
        assert UNCONFINED in reason
        assert "ASH's own mount namespace" in reason

    def test_firejails_existing_sandbox_warning_is_quoted_in_the_reason(
        self, linux_host
    ):
        linux_host(
            FakeFirejail(stdout=ASH_NAMESPACE + "\n", stderr=EXISTING_SANDBOX_WARNING)
        )
        reason = FirejailBackend().probe()
        assert reason is not None
        assert UNCONFINED in reason
        assert EXISTING_SANDBOX_WARNING in reason

    def test_the_warning_alone_is_enough_to_refuse(self, linux_host):
        # Whatever the namespace check made of the output, firejail saying it ran
        # without a sandbox is believed.
        linux_host(
            FakeFirejail(
                stdout=SANDBOX_NAMESPACE + "\n", stderr=EXISTING_SANDBOX_WARNING
            )
        )
        reason = FirejailBackend().probe()
        assert reason is not None
        assert EXISTING_SANDBOX_WARNING in reason

    def test_output_without_a_namespace_is_not_taken_as_confined(self, linux_host):
        linux_host(FakeFirejail(stdout="", returncode=0))
        reason = FirejailBackend().probe()
        assert reason is not None
        assert "could not confirm" in reason

    def test_a_firejail_that_cannot_start_is_unavailable_with_its_error(
        self, linux_host
    ):
        error = "Error: seccomp feature is disabled in Firejail configuration file"
        linux_host(FakeFirejail(stderr=error, returncode=1))
        reason = FirejailBackend().probe()
        assert reason is not None
        assert error in reason

    def test_a_command_in_its_own_mount_namespace_keeps_firejail_available(
        self, linux_host
    ):
        linux_host(confined())
        assert FirejailBackend().probe() is None

    def test_the_probe_command_runs_under_the_options_a_scan_gets(self, linux_host):
        fake = linux_host(confined())
        assert FirejailBackend().probe() is None
        (argv,) = fake.calls
        assert argv[0] == "/usr/bin/firejail"
        for flag in (
            "--noprofile",
            "--private-dev",
            "--nonewprivs",
            "--caps.drop=all",
            "--seccomp",
            "--nogroups",
            "--dbus-user=none",
            "--dbus-system=none",
            "--read-only=/",
            "--net=none",
            "--private",
            "--private-tmp",
        ):
            assert flag in argv
        # Not quiet, so that firejail's warning reaches the reason when it prints one.
        assert "--quiet" not in argv
        separator = argv.index("--")
        assert Path(argv[separator + 1]).name == "readlink"
        assert argv[separator + 2 :] == ["/proc/self/ns/mnt"]

    def test_a_refused_probe_leaves_nothing_to_plan_with(self, linux_host):
        linux_host(unconfined())
        backend = FirejailBackend()
        assert backend.probe() is not None
        with pytest.raises(RuntimeError, match="probe"):
            backend.plan(["/usr/bin/true"], {}, SimpleNamespace())  # type: ignore[arg-type]


class TestFirejailModes:
    def test_explicit_firejail_refuses_with_the_reason(self, linux_host):
        linux_host(unconfined())
        with pytest.raises(SandboxUnavailable, match=UNCONFINED):
            resolve_backend("firejail")

    def test_explicit_firejail_makes_the_scanner_missing_with_the_reason(
        self, linux_host, tmp_path
    ):
        # The scanner executor records a scanner MISSING with the message of the
        # SandboxUnavailable that scanner_sandbox_scope raises, and never runs it.
        linux_host(unconfined())
        with pytest.raises(SandboxUnavailable, match=UNCONFINED):
            scanner_sandbox_scope(_plugin(), _context(tmp_path, "firejail"), tmp_path)

    def test_explicit_firejail_makes_dependency_probes_refuse(
        self, linux_host, tmp_path
    ):
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            active_scope,
            plugin_probe_scope,
        )

        linux_host(unconfined())
        with plugin_probe_scope(_plugin(), _context(tmp_path, "firejail")):
            active = active_scope()
            assert isinstance(active, RefusingScope)
            assert UNCONFINED in active.reason

    def test_auto_moves_past_an_unconfining_firejail(self, linux_host, monkeypatch):
        linux_host(unconfined())
        monkeypatch.setattr(BwrapBackend, "probe", lambda self: "bwrap is absent")
        monkeypatch.setattr(LandlockBackend, "probe", lambda self: None)
        assert isinstance(resolve_backend("auto"), LandlockBackend)

    def test_auto_fails_closed_when_nothing_after_firejail_works(
        self, linux_host, monkeypatch
    ):
        linux_host(unconfined())
        monkeypatch.setattr(BwrapBackend, "probe", lambda self: "bwrap is absent")
        monkeypatch.setattr(LandlockBackend, "probe", lambda self: "no Landlock")
        with pytest.raises(SandboxUnavailable) as raised:
            resolve_backend("auto")
        message = str(raised.value)
        assert "firejail: " in message
        assert UNCONFINED in message

    def test_auto_uses_a_firejail_that_confines(self, linux_host, monkeypatch):
        linux_host(confined())
        monkeypatch.setattr(BwrapBackend, "probe", lambda self: "bwrap is absent")
        monkeypatch.setattr(LandlockBackend, "probe", lambda self: None)
        assert isinstance(resolve_backend("auto"), FirejailBackend)
