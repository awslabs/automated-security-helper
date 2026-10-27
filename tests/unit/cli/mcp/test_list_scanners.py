# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for mcp_list_scanners."""

import json
import stat
import subprocess  # nosec B404 - the snapshot runs this test's own interpreter
import sys
import textwrap
from dataclasses import dataclass
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

import automated_security_helper
from automated_security_helper.cli.mcp_tools import mcp_list_scanners
from automated_security_helper.core.enums import OfflineStrategy
from tests.utils.helpers import importing_this_checkout

KNOWN_SCANNERS = {
    "bandit",
    "cdk_nag",
    "cfn_nag",
    "checkov",
    "detect_secrets",
    "ferret_scan",
    "grype",
    "npm_audit",
    "opengrep",
    "semgrep",
    "snyk_code",
    "syft",
    "trivy_repo",
}

REQUIRED_KEYS = {
    "name",
    "version",
    "dependencies_satisfied",
    "offline_strategy",
    "enabled",
}
VALID_OFFLINE_STRATEGIES = {s.value for s in OfflineStrategy}


# ---------------------------------------------------------------------------
# The snapshot: the real scanner classes, asking stand-in tools
# ---------------------------------------------------------------------------
#
# A snapshot from mcp_list_scanners() run against whatever the host has
# installed would start a real process per dependency check and version probe:
# `uv tool run bandit|checkov|detect-secrets|semgrep --version`, `uv tool list`,
# and cfn_nag_scan, grype, npm, opengrep, syft and trivy `--version` -- 18
# processes on one machine. What the tests below read would then be a fact about
# that machine, and a unit test cannot depend on which tools a host has.
#
# Every tool the scanners ask about is a stand-in: a shell script that logs
# its argv and prints a version. The stand-in uv reports bandit and checkov as
# installed and semgrep as not, so the snapshot holds a tool a first scan would
# install. snyk and node have no stand-in, so snyk_code and cdk_nag report their
# dependencies unsatisfied. The versions are distinct, so each one in the snapshot
# can be traced to the stand-in that printed it.

#: Tools the stand-in uv reports as installed, and the version each one prints.
UV_INSTALLED_TOOLS = {"bandit": "1.99.1", "checkov": "3.99.2"}

#: Stand-ins on PATH, and what each prints for ``--version``.
PATH_TOOLS = {
    "cfn_nag_scan": "0.99.4",
    "ferret-scan": "ferret-scan version 2.5.99",
    "grype": "grype 0.99.5",
    "npm": "10.99.6",
    "opengrep": "1.99.7",
    "syft": "syft 1.99.8",
    "trivy": "Version: 0.99.9",
}

#: Every uv-managed scanner's tool, installed or not. Each one is asked about.
UV_ASKED_TOOLS = ("bandit", "checkov", "semgrep")

#: What the stand-in log records when ASH's uv lookup reached the stand-in.
WITNESS = "stand-in-witness"

_STAND_IN_LOG_VAR = "LIST_SCANNERS_STAND_IN_LOG"


def _stand_in_script(name: str, answers: List[Tuple[str, str]]) -> str:
    """A POSIX shell stand-in for ``name``.

    It appends ``name`` and its arguments to the log, prints the output paired with
    the first ``case`` pattern its arguments match, and fails anything else with
    exit 2. Only shell builtins: PATH holds nothing but stand-ins.
    """
    branches = []
    for pattern, output in answers:
        assert "'" not in output, output
        lines = " ".join(f"'{line}'" for line in output.splitlines())
        branches.append(f"  {pattern}) printf '%s\\n' {lines}; exit 0 ;;")
    return (
        "#!/bin/sh\n"
        f'printf \'%s\\n\' "{name} $*" >> "${_STAND_IN_LOG_VAR}"\n'
        'case "$*" in\n' + "\n".join(branches) + "\nesac\n"
        f'echo "stand-in {name} refuses: $*" >&2\n'
        "exit 2\n"
    )


def _uv_answers() -> List[Tuple[str, str]]:
    """``uv --version``, ``uv tool list``, and an offline ``tool run`` per tool."""
    listing = "\n".join(
        f"{tool} v{release}\n- {tool}" for tool, release in UV_INSTALLED_TOOLS.items()
    )
    answers = [("--version", "uv 0.9.99"), ('"tool list"', listing)]
    for tool, release in UV_INSTALLED_TOOLS.items():
        # With or without --from: the constructor's probe names the scan's spec.
        answers.append(
            (f'"tool run --offline"*" {tool} --version"', f"{tool} {release}")
        )
    return answers


def _install_stand_ins(directory: Path) -> None:
    directory.mkdir()
    scripts = {"uv": _stand_in_script("uv", _uv_answers())}
    for tool, output in PATH_TOOLS.items():
        scripts[tool] = _stand_in_script(tool, [("--version", output)])
    for tool, text in scripts.items():
        path = directory / tool
        path.write_text(text, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@dataclass(frozen=True)
class _Snapshot:
    entries: List[dict]
    #: Every process the snapshot's code started: phase, argv, and the executable
    #: the argv resolved to.
    spawned: List[dict]
    stand_ins: Path
    #: What the stand-ins logged, one call per line.
    calls: List[str]
    #: The uv ASH's own lookup returned once the inventory had run.
    uv_found: Optional[str]

    def started(self, phase: str) -> List[dict]:
        return [record for record in self.spawned if record["phase"] == phase]

    def is_stand_in(self, record: dict) -> bool:
        resolved = record["resolved"]
        return (
            resolved is not None
            and Path(resolved).resolve().parent == self.stand_ins.resolve()
        )


#: Runs mcp_list_scanners() in the child and writes what it returned, every process
#: it started, and the uv ASH's lookup found, to the file named by argv[2].
_SNAPSHOT_DRIVER = textwrap.dedent(
    f"""\
    import json
    import os
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    # The package the test imported, not whichever copy -I finds first.
    sys.path.insert(0, sys.argv[1])
    output = Path(sys.argv[2])

    spawned = []
    phase = "inventory"
    popen_init = subprocess.Popen.__init__


    def recording_init(self, args, *rest, **kwargs):
        argv = [args] if isinstance(args, (str, bytes, os.PathLike)) else list(args)
        argv = [os.fsdecode(arg) for arg in argv]
        program = os.fsdecode(kwargs.get("executable") or argv[0])
        env = kwargs.get("env")
        if env is None:
            env = os.environ
        resolved = shutil.which(program, path=env.get("PATH", os.defpath))
        spawned.append({{"phase": phase, "argv": argv, "resolved": resolved}})
        return popen_init(self, args, *rest, **kwargs)


    subprocess.Popen.__init__ = recording_init

    from automated_security_helper.utils import subprocess_utils, uv_tool_runner

    # find_executable falls back to ASH's bin directory and /usr/local/bin whatever
    # PATH says, so a tool installed there would answer instead of a stand-in.
    subprocess_utils.path_independent_dirs = lambda: []
    # ASH can look for the uv installed beside this interpreter before PATH.
    if hasattr(uv_tool_runner, "bundled_uv_executable"):
        uv_tool_runner.bundled_uv_executable = lambda: None

    from automated_security_helper.cli.mcp_tools import mcp_list_scanners

    entries = mcp_list_scanners()

    phase = "control"
    uv_found = uv_tool_runner.find_uv_or_none()
    if uv_found:
        subprocess.run([uv_found, "{WITNESS}"], capture_output=True, check=False)
    subprocess.run([sys.executable, "-c", "pass"], check=False)

    output.write_text(
        json.dumps({{"entries": entries, "spawned": spawned, "uv_found": uv_found}}),
        encoding="utf-8",
    )
    """
)


def _take_snapshot(root: Path) -> _Snapshot:
    """mcp_list_scanners() in a child whose PATH holds only the stand-ins.

    A child rather than this process because the answers are cached at module
    level -- ``find_executable``'s lookups, ``find_uv_or_none``, the shared
    ``UVToolRunner``'s "is uv available" -- so an in-process run could be served a
    real tool another test had already found, and would leave stand-in paths in
    the caches for every later test on this worker. The child starts with empty
    caches and takes them with it.

    Its environment is built from nothing: HOME, TMPDIR and ASH's bin directory are
    scratch directories, and no ASH_OFFLINE, UV_* or XDG_* setting of this process
    reaches it. The entries come back as JSON, which is also how an MCP client
    receives them.
    """
    stand_ins = root / "stand-ins"
    _install_stand_ins(stand_ins)
    for scratch in ("home", "tmp", "ash-bin", "cwd"):
        (root / scratch).mkdir()
    log = root / "stand-ins.log"
    log.write_text("", encoding="utf-8")
    result_file = root / "snapshot.json"
    package_parent = Path(automated_security_helper.__file__).resolve().parent.parent

    result = subprocess.run(  # nosec B603 - fixed argv, this test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(_SNAPSHOT_DRIVER),
            str(package_parent),
            str(result_file),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=root / "cwd",
        env={
            "PATH": str(stand_ins),
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "ASH_BIN_PATH": str(root / "ash-bin"),
            _STAND_IN_LOG_VAR: str(log),
        },
    )
    if result.returncode != 0:
        pytest.fail(
            f"the snapshot child exited {result.returncode}:\n{result.stderr[-4000:]}"
        )
    data = json.loads(result_file.read_text(encoding="utf-8"))
    return _Snapshot(
        entries=data["entries"],
        spawned=data["spawned"],
        stand_ins=stand_ins,
        calls=[line for line in log.read_text(encoding="utf-8").splitlines() if line],
        uv_found=data["uv_found"],
    )


@pytest.fixture(scope="module")
def snapshot(tmp_path_factory) -> _Snapshot:
    if sys.platform == "win32":
        pytest.skip("the stand-ins are POSIX shell scripts")
    return _take_snapshot(tmp_path_factory.mktemp("list-scanners"))


@pytest.fixture(scope="module")
def scanners(snapshot):
    """One mcp_list_scanners() snapshot, shared by every test that reads it.

    Taken against stand-ins (see ``_take_snapshot``), so it is the same on every
    machine. Module-scoped because each snapshot is a child process that imports
    ASH and constructs all 13 scanners, and every test below asserts about the one
    observation without changing it. The stub-injection tests deliberately do NOT
    use it -- they replace the discovered scanner set, so they need their own call.

    What the host's real tools report is asserted in
    tests/integration/scanners/test_list_scanners_installed_tools.py, which runs
    only with ``--run-integration``.
    """
    return snapshot.entries


class TestListScannersSchema:
    def test_returns_list(self, scanners):
        assert isinstance(scanners, list)

    def test_at_least_13_entries(self, scanners):
        assert len(scanners) >= 13

    def test_each_entry_has_required_keys(self, scanners):
        for entry in scanners:
            missing = REQUIRED_KEYS - entry.keys()
            assert not missing, f"Entry {entry.get('name')} missing keys: {missing}"

    def test_offline_strategy_values_are_valid(self, scanners):
        for entry in scanners:
            assert entry["offline_strategy"] in VALID_OFFLINE_STRATEGIES, (
                f"Scanner {entry.get('name')} has invalid offline_strategy: {entry['offline_strategy']}"
            )

    def test_all_known_scanners_present(self, scanners):
        names = {entry["name"] for entry in scanners}
        missing = KNOWN_SCANNERS - names
        assert not missing, f"Missing scanners: {missing}"


class TestListScannersPerScanner:
    def _get_by_name(self, scanners: list, name: str) -> dict:
        matches = [e for e in scanners if e["name"] == name]
        assert matches, f"Scanner '{name}' not found in list_scanners result"
        return matches[0]

    def test_bandit_offline_strategy_is_bundled(self, scanners):
        entry = self._get_by_name(scanners, "bandit")
        assert entry["offline_strategy"] == OfflineStrategy.BUNDLED.value

    def test_snyk_code_offline_strategy_is_skip_offline(self, scanners):
        entry = self._get_by_name(scanners, "snyk_code")
        assert entry["offline_strategy"] == OfflineStrategy.SKIP_OFFLINE.value

    def test_checkov_offline_strategy_is_cache_flags(self, scanners):
        entry = self._get_by_name(scanners, "checkov")
        assert entry["offline_strategy"] == OfflineStrategy.CACHE_FLAGS.value

    def test_enabled_is_bool(self, scanners):
        for entry in scanners:
            assert isinstance(entry["enabled"], bool), (
                f"Scanner {entry.get('name')} enabled is not bool: {entry['enabled']}"
            )

    def test_dependencies_satisfied_is_bool_or_none(self, scanners):
        """Tri-state: True, False, or None for "could not determine".

        Widened from bool-only when the field started being measured. None is
        reported for a scanner that could not be constructed or whose check
        raised, because reporting False there is the defect this area had: it
        under-reports capability and reads as a measurement.
        """
        for entry in scanners:
            assert entry["dependencies_satisfied"] in (True, False, None), (
                f"Scanner {entry.get('name')} dependencies_satisfied is "
                f"{entry['dependencies_satisfied']!r}"
            )

    def test_version_is_none_or_str(self, scanners):
        for entry in scanners:
            assert entry["version"] is None or isinstance(entry["version"], str), (
                f"Scanner {entry.get('name')} version has unexpected type: {type(entry['version'])}"
            )


# ---------------------------------------------------------------------------
# The fields are measured, not defaulted
# ---------------------------------------------------------------------------
#
# Why this section exists
# ----------------------
# mcp_list_scanners used to return the literals None for every version and False
# for every dependencies_satisfied. Measured against a deployed server, all 13
# scanners reported dependencies_satisfied false while a real scan in the same
# runtime completed 10 of 10 scanners -- so an operator checking their deployment
# with this tool concluded a working image was broken, and the failure pointed the
# wrong way, toward a rebuild that would fix nothing.
#
# The two type assertions above are exactly why it survived. "is a bool" passes
# against a hardcoded False, and "is None or str" passes against a hardcoded None.
# A type assertion over a constant cannot fail. Every test below asserts a *value*,
# and the injection tests assert two different values from one call, which no
# constant can satisfy.


class _StubConfig:
    def __init__(self, name, enabled=True):
        self.name = name
        self.enabled = enabled


class _StubScanner:
    """Minimal stand-in for a scanner plugin.

    ``_describe_scanner`` reaches its subject entirely through getattr and a
    constructor call, so a plain object is enough. Using stubs rather than real
    scanners is what makes the polarity tests independent of which tools happen to
    be installed on the machine running them.
    """

    offline_strategy = None
    _name = "stub"
    _satisfied = True
    _version = None
    _raise_on_validate = False
    _raise_on_init = False

    def __init__(self, context=None):
        if self._raise_on_init:
            raise RuntimeError("stub refuses to be constructed")
        self.config = _StubConfig(self._name)
        self.tool_version = self._version

    def validate_plugin_dependencies(self):
        if self._raise_on_validate:
            raise RuntimeError("stub dependency check exploded")
        return self._satisfied


def _stub(name, **attrs):
    return type(f"{name}Scanner", (_StubScanner,), {"_name": name, **attrs})


@pytest.fixture
def injected(monkeypatch):
    """Replace the discovered scanner set with the given stub classes."""

    def _install(*classes):
        monkeypatch.setattr(
            "automated_security_helper.cli.mcp_tools._loaded_scanner_classes",
            lambda: list(classes),
        )
        return {entry["name"]: entry for entry in mcp_list_scanners()}

    return _install


class TestDependenciesSatisfiedIsMeasured:
    def test_both_polarities_are_reported_from_one_call(self, injected):
        """The decisive test: two scanners, two different answers.

        A fixture where every scanner agrees cannot tell which signal the code
        reads -- an all-unsatisfied fixture passes against code returning False
        unconditionally, which is precisely how the defect went unnoticed. One
        satisfied and one unsatisfied scanner in the same result cannot both be a
        constant.
        """
        entries = injected(
            _stub("yes_scanner", _satisfied=True),
            _stub("no_scanner", _satisfied=False),
        )

        assert entries["yes_scanner"]["dependencies_satisfied"] is True
        assert entries["no_scanner"]["dependencies_satisfied"] is False

    def test_the_method_is_called_not_the_attribute_read(self, injected):
        """``dependencies_satisfied`` on the plugin is a default, not an answer.

        ``ScannerPluginBase`` declares ``dependencies_satisfied: bool = False``, so
        the attribute holds False for every scanner until ``ScanPhase`` assigns the
        method's return value onto it. A tool that read the attribute would report
        False for a perfectly working scanner. This stub sets the attribute to the
        wrong value on purpose, so reading it cannot pass.
        """
        cls = _stub("disagreeing", _satisfied=True)
        original_init = cls.__init__

        def _init(self, context=None):
            original_init(self, context=context)
            self.dependencies_satisfied = False

        cls.__init__ = _init
        entries = injected(cls)

        assert entries["disagreeing"]["dependencies_satisfied"] is True

    def test_a_check_that_raises_reports_none_not_false(self, injected):
        """Unmeasurable is not the same as unsatisfied.

        Some scanners raise ScannerError from their dependency check instead of
        returning False. Collapsing that onto False is what makes a tool's output
        unable to distinguish "this is broken" from "I could not tell".
        """
        entries = injected(_stub("exploding", _raise_on_validate=True))
        assert entries["exploding"]["dependencies_satisfied"] is None

    def test_a_scanner_that_cannot_be_constructed_is_still_listed(self, injected):
        """Present with None, rather than dropped.

        A scanner missing from the list reads as "this build has 12 scanners",
        which is a wrong answer. Present with None reads as "could not determine",
        which is the true one. The name comes from the class name in this case.
        """
        entries = injected(
            _stub("broken", _raise_on_init=True), _stub("fine", _satisfied=True)
        )

        assert set(entries) == {"broken", "fine"}
        assert entries["broken"]["dependencies_satisfied"] is None
        assert entries["fine"]["dependencies_satisfied"] is True

    def test_one_broken_scanner_does_not_fail_the_whole_tool(self, injected):
        """Per-scanner isolation. The tool is read-only introspection; a single
        misbehaving plugin must not turn it into an error response."""
        entries = injected(
            _stub("boom", _raise_on_init=True),
            _stub("bang", _raise_on_validate=True),
            _stub("ok", _satisfied=True),
        )
        assert len(entries) == 3
        assert entries["ok"]["dependencies_satisfied"] is True


class TestVersionIsMeasured:
    def test_versions_are_reported_and_differ_per_scanner(self, injected):
        entries = injected(
            _stub("alpha", _version="1.2.3"), _stub("beta", _version="9.9.9")
        )
        assert entries["alpha"]["version"] == "1.2.3"
        assert entries["beta"]["version"] == "9.9.9"

    def test_trailing_whitespace_is_stripped(self, injected):
        """At least one scanner assigns the raw stdout of a --version subprocess,
        newline included."""
        entries = injected(_stub("noisy", _version="10.9.4\n"))
        assert entries["noisy"]["version"] == "10.9.4"

    @pytest.mark.parametrize("marker", ["", "  ", "unavailable", "unknown", "none"])
    def test_absence_markers_become_none(self, injected, marker):
        """One representation for "no version", not four a caller must each know."""
        entries = injected(_stub("absent", _version=marker))
        assert entries["absent"]["version"] is None

    def test_a_version_set_during_the_dependency_check_is_captured(self, injected):
        """Version must be read AFTER validate_plugin_dependencies, not before.

        npm-audit shells out to ``npm --version`` inside its dependency check and
        assigns the result to ``tool_version``; before that call the attribute is
        None. Reading version first therefore reports None for every scanner that
        detects its version that way, which is how the ordering bug was found -- the
        reported version set was missing npm-audit's while a probe that validated
        first could see it.

        This stub reproduces that mechanism rather than relying on npm being
        installed, so the guard holds on a machine with no node toolchain.
        """
        cls = _stub("late_version", _satisfied=True, _version=None)
        base_validate = cls.validate_plugin_dependencies

        def _validate(self):
            self.tool_version = "7.7.7"
            return base_validate(self)

        cls.validate_plugin_dependencies = _validate
        entries = injected(cls)

        assert entries["late_version"]["version"] == "7.7.7"


class TestTheSnapshotStartsOnlyStandIns:
    """Nothing the snapshot ran reached a tool on the host."""

    def test_no_process_but_a_stand_in_was_started(self, snapshot):
        started = snapshot.started("inventory")
        assert started, (
            "the inventory started no process at all, so this check would pass "
            "without having watched anything"
        )
        outside = [
            f"{' '.join(record['argv'])} -> {record['resolved']}"
            for record in started
            if not snapshot.is_stand_in(record)
        ]
        assert not outside, (
            f"mcp_list_scanners() started {len(outside)} process(es) that are not "
            "stand-ins:\n" + "\n".join(outside)
        )

    def test_the_guard_reports_a_process_that_is_not_a_stand_in(self, snapshot):
        """The control: after the inventory, the child starts its own interpreter.

        Without it, the test above could pass because the recording missed every
        spawn, or because every resolved path happened to compare as a stand-in.
        """
        control = [
            record
            for record in snapshot.started("control")
            if record["argv"][1:] == ["-c", "pass"]
        ]
        assert len(control) == 1, snapshot.spawned
        assert not snapshot.is_stand_in(control[0]), control

    def test_ash_finds_the_stand_in_uv(self, snapshot):
        """ASH's uv lookup may try the uv installed beside the interpreter first.

        The child turns that lookup off, then calls whatever uv ASH finds with
        WITNESS. Only the stand-in logs it.
        """
        assert snapshot.uv_found is not None
        assert (
            Path(snapshot.uv_found).resolve() == (snapshot.stand_ins / "uv").resolve()
        )
        assert f"uv {WITNESS}" in snapshot.calls, snapshot.calls

    def test_each_stand_in_on_path_was_asked_its_version(self, snapshot):
        unasked = [
            tool for tool in PATH_TOOLS if f"{tool} --version" not in snapshot.calls
        ]
        assert not unasked, snapshot.calls

    def test_uv_was_asked_about_each_uv_managed_tool(self, snapshot):
        assert "uv tool list" in snapshot.calls, snapshot.calls
        for tool in UV_ASKED_TOOLS:
            asked = [
                call
                for call in snapshot.calls
                if call.startswith("uv tool run --offline ")
                and call.endswith(f" {tool} --version")
            ]
            assert asked, f"uv was never asked for {tool}'s version: {snapshot.calls}"


def _expected_entries() -> Dict[str, Tuple[Optional[str], Optional[bool], bool]]:
    """Each scanner's (version, dependencies_satisfied, installs_on_first_scan).

    Two versions come from ASH's own Python dependencies rather than a stand-in:
    detect-secrets runs in-process from the installed library, and cdk_nag reports
    the cdk-nag distribution when the ``cdk`` extra is installed.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cdk_nag_scanner,
    )

    cdk_nag_version = (
        distribution_version("cdk-nag") if cdk_nag_scanner._CDK_AVAILABLE else None
    )
    return {
        "bandit": ("1.99.1", True, False),
        # No node stand-in, so unsatisfied with or without the cdk extra.
        "cdk_nag": (cdk_nag_version, False, False),
        "cfn_nag": ("0.99.4", True, False),
        "checkov": ("3.99.2", True, False),
        "detect_secrets": (distribution_version("detect-secrets"), True, False),
        "ferret_scan": ("2.5.99", True, False),
        "grype": ("0.99.5", True, False),
        "npm_audit": ("10.99.6", True, False),
        "opengrep": ("1.99.7", True, False),
        # Not installed in uv, uv is present and the run is online: a scan
        # installs it, and the inventory says so instead of installing it.
        "semgrep": (None, False, True),
        "snyk_code": (None, False, False),
        "syft": ("1.99.8", True, False),
        "trivy_repo": ("0.99.9", True, False),
    }


class TestMeasuredAgainstTheStandIns:
    """Value assertions against the real scanner classes, not stubs.

    The stub tests prove the fields are computed. These prove the computation is
    wired to the actual scanners -- a correct ``_describe_scanner`` that
    ``mcp_list_scanners`` never called would pass every test above -- and, because
    every value traces to one stand-in, that each scanner asked its own tool.
    """

    def test_every_scanner_reports_what_its_stand_in_answered(self, scanners):
        reported = {
            entry["name"]: (
                entry["version"],
                entry["dependencies_satisfied"],
                entry["installs_on_first_scan"],
            )
            for entry in scanners
        }
        assert reported == _expected_entries()

    def test_bandit_reports_its_dependencies_as_satisfied(self, scanners):
        """The sharpest single assertion against the old behavior.

        The hardcoded value was False; the stand-in uv lists bandit as installed,
        so the measured value is True.
        """
        entry = next(e for e in scanners if e["name"] == "bandit")
        assert entry["dependencies_satisfied"] is True

    def test_bandit_reports_the_version_its_tool_printed(self, scanners):
        entry = next(e for e in scanners if e["name"] == "bandit")
        assert entry["version"] == UV_INSTALLED_TOOLS["bandit"]

    def test_not_every_scanner_reports_the_same_dependency_state(self, scanners):
        """The stand-ins leave snyk, node and uv's semgrep out on purpose.

        So a uniform answer across all 13 means the field is not being measured --
        which is the exact shape of the original defect.
        """
        states = {e["dependencies_satisfied"] for e in scanners}
        assert len(states) > 1, (
            f"every scanner reported dependencies_satisfied={states}, which is a "
            f"constant rather than a measurement"
        )
