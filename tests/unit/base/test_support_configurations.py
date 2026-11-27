"""One fixture per configuration: the rows it raises, and the ways out it is offered.

Each case plants the facts of one environment (what a reader of the host would
return) and asserts the exact rows the evaluator gives, with their levels and
behaviors, and the upgrade paths offered where it matters. Nothing here reads the
machine the tests run on.

The declared rows are also pinned as a table, so a change to a level, a behavior,
the moment a row is raised, who sees it or which paths it offers shows in review
as a change to this file and not only to the register.
"""

from __future__ import annotations

import functools
from dataclasses import replace
from typing import Any

import pytest

from automated_security_helper.base import support_register as sr
from tests.utils.scanner_enumeration import load_scanner_universe
from tests.utils.support_gaps import (
    UNALLOWED_GAP,
    all_platforms_but,
    pinned_binaries,
    unallowed_gap_rows,
)

pytestmark = pytest.mark.unit


def _facts(**overlay: str) -> sr.HostFacts:
    """The reference facts with ``overlay`` on them, settled as a run's are."""
    return sr.settle(replace(sr.REFERENCE_FACTS, **overlay))


def _raised(facts: sr.HostFacts, scope: str = "ash") -> list[tuple[str, str, str]]:
    """The rows a run raises, at start or at a decision, worst first."""
    found = sr.evaluate(facts, scope, notify=(sr.Notify.START, sr.Notify.DECISION))
    return [(e.row.id, e.row.level.value, e.row.behavior.value) for e in found]


def _offered(facts: sr.HostFacts, row_id: str, scope: str = "ash") -> list[str] | None:
    """The ids of the paths offered for ``row_id`` on ``facts``, or None when the
    row does not match."""
    for found in sr.evaluate(facts, scope):
        if found.row.id == row_id:
            return [path.id for path in found.paths]
    return None


WINDOWS = {"os": "windows", "host_os": "windows", "express_available": "no"}
MACOS = {"os": "darwin", "host_os": "darwin"}
#: A Windows host that runs the container image: the scanners run in the image's Linux.
WINDOWS_IMAGE = {"os": "linux", "host_os": "windows", "express_available": "no"}

CPU = ("host.cpu.below-polars-runtime", "unsupported", "continues")
CPU_COMPAT = ("host.cpu.below-polars-compat", "unsupported", "continues")
COMPAT_RUNTIME = ("host.cpu.polars-compat-runtime", "polyfilled", "continues")
ROSETTA = ("host.translation.rosetta", "degraded", "continues")
X64_ON_ARM64 = ("host.translation.x64-on-arm64", "degraded", "continues")
OTHER_OS = ("host.os.other", "unsupported", "continues")
OTHER_ARCH = ("host.arch.other", "unsupported", "continues")
PYTHON = ("host.python.outside-requires", "unsupported", "continues")
NIX = ("host.mode.nix-on-windows", "unsupported", "refuses")
IN_CONTAINER = ("host.sandbox.not-applied-in-container", "degraded", "continues")
NO_BACKEND_AUTO = ("host.sandbox.unavailable-auto", "unsupported", "scanner-missing")
NO_BACKEND_NAMED = ("host.sandbox.unavailable-named", "unsupported", "scanner-error")
LANDLOCK = ("host.sandbox.landlock-below-6", "degraded", "continues")
BWRAP_CACHES = ("host.sandbox.bwrap-caches-read-only", "degraded", "continues")
EXPRESS = ("host.express.unavailable", "degraded", "continues")
POWERSHELL_5 = ("host.shell.powershell-5", "polyfilled", "continues")
MSYS = ("host.shell.msys", "polyfilled", "continues")
IMAGE_ARCH = ("host.container.image-arch-mismatch", "degraded", "continues")

# (configuration, the facts it plants, the rows a run raises there)
CASES: list[tuple[str, dict[str, str], list[tuple[str, str, str]]]] = [
    ("the reference environment", {}, []),
    ("linux x86-64 without avx2", {"arch": "amd64", "cpu_level": "compat-only"}, [CPU]),
    (
        "linux x86-64 without sse4.2, the default runtime",
        {"arch": "amd64", "cpu_level": "below-compat"},
        [CPU],
    ),
    (
        "linux x86-64 without sse4.2, the compatibility runtime",
        {"arch": "amd64", "cpu_level": "below-compat", "polars_runtime": "compat"},
        [CPU_COMPAT],
    ),
    (
        "a forced default runtime on a compat-only processor",
        {"cpu_level": "compat-only", "polars_runtime": "runtime-32"},
        [CPU],
    ),
    (
        "the compatibility runtime on a compat-only processor",
        {"cpu_level": "compat-only", "polars_runtime": "compat"},
        [COMPAT_RUNTIME],
    ),
    (
        "the compatibility runtime on a full processor",
        {"cpu_level": "full", "polars_runtime": "compat"},
        [COMPAT_RUNTIME],
    ),
    ("macos arm64 native", {**MACOS, "arch": "arm64"}, []),
    ("macos intel", {**MACOS, "arch": "amd64"}, []),
    (
        "macos, x86-64 python under rosetta",
        {**MACOS, "arch": "amd64", "translation": "rosetta"},
        [ROSETTA],
    ),
    (
        "macos, x86-64 python under rosetta, a needed flag missing",
        {
            **MACOS,
            "arch": "amd64",
            "translation": "rosetta",
            "cpu_level": "compat-only",
        },
        [CPU, ROSETTA],
    ),
    ("windows amd64, local", {**WINDOWS, "arch": "amd64"}, []),
    ("windows arm64 native", {**WINDOWS, "arch": "arm64"}, []),
    (
        "windows, x64 python on arm64",
        {**WINDOWS, "arch": "amd64", "translation": "x64-on-arm64"},
        [X64_ON_ARM64],
    ),
    ("linux with musl", {"libc": "musl"}, []),
    ("wsl 1", {"wsl": "wsl1"}, []),
    ("wsl 2", {"wsl": "wsl2"}, []),
    ("free-threaded cpython", {"python_build": "free-threaded"}, []),
    ("another python implementation", {"python_build": "other-implementation"}, []),
    ("python outside the declared range", {"python_in_range": "no"}, [PYTHON]),
    ("freebsd on x86-64", {"os": "other", "host_os": "other"}, [OTHER_OS]),
    ("linux on a processor polars has no build for", {"arch": "other"}, [OTHER_ARCH]),
    (
        "another operating system and processor",
        {"os": "other", "host_os": "other", "arch": "other"},
        [OTHER_OS, OTHER_ARCH],
    ),
    (
        "container mode with a sandbox asked for",
        {"run_mode": "container", "sandbox_mode": "auto"},
        [IN_CONTAINER],
    ),
    (
        "container mode with a named sandbox",
        {"run_mode": "container", "sandbox_mode": "named"},
        [IN_CONTAINER],
    ),
    (
        "a sandbox asked for and no backend on linux",
        {"sandbox_mode": "auto", "sandbox_backend": "none"},
        [NO_BACKEND_AUTO],
    ),
    (
        "a named sandbox and no backend on linux",
        {"sandbox_mode": "named", "sandbox_backend": "none"},
        [NO_BACKEND_NAMED],
    ),
    (
        "a sandbox asked for and no backend on windows",
        {**WINDOWS, "sandbox_mode": "auto", "sandbox_backend": "none"},
        [NO_BACKEND_AUTO],
    ),
    (
        "container mode on windows with a sandbox asked for and no host backend",
        {
            **WINDOWS_IMAGE,
            "run_mode": "container",
            "sandbox_mode": "auto",
            "sandbox_backend": "none",
        },
        [IN_CONTAINER],
    ),
    (
        "container mode on windows with a named sandbox and no host backend",
        {
            **WINDOWS_IMAGE,
            "run_mode": "container",
            "sandbox_mode": "named",
            "sandbox_backend": "none",
        },
        [IN_CONTAINER],
    ),
    (
        "container mode on macos with a sandbox asked for and no host backend",
        {
            "os": "linux",
            "host_os": "darwin",
            "run_mode": "container",
            "sandbox_mode": "auto",
            "sandbox_backend": "none",
        },
        [IN_CONTAINER],
    ),
    (
        "landlock abi 5",
        {
            "sandbox_mode": "auto",
            "sandbox_backend": "landlock",
            "sandbox_loss": "landlock-below-6",
        },
        [LANDLOCK],
    ),
    (
        "bubblewrap without the cache overlay",
        {
            "sandbox_mode": "auto",
            "sandbox_backend": "bwrap",
            "sandbox_loss": "caches-read-only",
        },
        [BWRAP_CACHES],
    ),
    (
        "express asked for on windows",
        {**WINDOWS, "express_requested": "yes"},
        [EXPRESS],
    ),
    ("nix mode on windows", {**WINDOWS, "run_mode": "nix"}, [NIX]),
    (
        "the powershell 5.1 wrapper",
        {**WINDOWS, "shell": "powershell-5"},
        [POWERSHELL_5],
    ),
    ("the git bash wrapper", {**WINDOWS, "shell": "msys-wrapper"}, [MSYS]),
    (
        "container mode with an image of another architecture",
        {"run_mode": "container", "image_arch_matches": "no"},
        [IMAGE_ARCH],
    ),
]


@pytest.mark.parametrize(
    ("overlay", "expected"),
    [pytest.param(o, e, id=name) for name, o, e in CASES],
)
def test_a_configuration_raises_exactly_its_rows(
    overlay: dict[str, str], expected: list[tuple[str, str, str]]
) -> None:
    assert _raised(_facts(**overlay)) == expected


SEMGREP_WINDOWS = ("scanner.semgrep.windows", "unsupported", "skips-scanner")
GUARDDOG_WINDOWS = ("scanner.guarddog.windows", "unsupported", "skips-scanner")
GUARDDOG_REPLACED = ("scanner.guarddog.sandbox-replaced", "polyfilled", "continues")
GUARDDOG_NO_SANDBOX = ("scanner.guarddog.sandbox-unavailable", "degraded", "continues")
BETTERLEAKS_HOME = ("scanner.betterleaks.private-home", "polyfilled", "continues")
IGNORE_PATHS_TOOLS = ("trivy", "trivy-repo", "checkov", "ferret-scan")

#: macOS on Apple silicon with a sandbox asked for and sandbox-exec as its backend.
MACOS_SANDBOXED = {
    **MACOS,
    "arch": "arm64",
    "sandbox_mode": "auto",
    "sandbox_backend": "sandbox-exec",
}


def _ignore_paths(tool: str) -> tuple[str, str, str]:
    return (f"scanner.{tool}.windows-ignore-paths", "degraded", "continues")


# (configuration, the scanner, the facts it plants, the rows a run raises there)
SCANNER_CASES: list[tuple[str, str, dict[str, str], list[tuple[str, str, str]]]] = [
    ("semgrep on windows", "semgrep", {**WINDOWS}, [SEMGREP_WINDOWS]),
    ("guarddog on windows", "guarddog", {**WINDOWS}, [GUARDDOG_WINDOWS]),
    (
        "guarddog under sandbox-exec on macos",
        "guarddog",
        {**MACOS_SANDBOXED, "tool_sandbox": "replaced"},
        [GUARDDOG_REPLACED],
    ),
    (
        "guarddog without its kernel sandbox on linux",
        "guarddog",
        {"tool_sandbox": "unavailable"},
        [GUARDDOG_NO_SANDBOX],
    ),
    (
        "betterleaks under sandbox-exec on macos",
        "betterleaks",
        {**MACOS_SANDBOXED},
        [BETTERLEAKS_HOME],
    ),
    *(
        (
            f"{tool} with ignore paths on windows",
            tool,
            {**WINDOWS, "ignore_paths": "set"},
            [_ignore_paths(tool)],
        )
        for tool in IGNORE_PATHS_TOOLS
    ),
]


@pytest.mark.parametrize(
    ("scanner", "overlay", "expected"),
    [pytest.param(s, o, e, id=name) for name, s, o, e in SCANNER_CASES],
)
def test_a_scanner_configuration_raises_exactly_its_rows(
    scanner: str, overlay: dict[str, str], expected: list[tuple[str, str, str]]
) -> None:
    assert _raised(_facts(**overlay), scanner) == expected


def test_the_cases_cover_every_row_a_run_can_raise() -> None:
    """A row no case raises is a row nothing here holds, in whichever scope it is
    declared: a new row of a scanner, as of ASH, needs a configuration that raises it."""
    seen = {row[0] for _, _, rows in CASES for row in rows}
    seen |= {row[0] for _, _, _, rows in SCANNER_CASES for row in rows}
    declared = {
        row.id for row in sr.REGISTER.rows if row.notify is not sr.Notify.MATRIX
    }
    assert declared, "the register declares no row that a run raises"
    assert declared - seen == set()


# ---------------------------------------------------------------------------
# The ways out, where a configuration offers them
# ---------------------------------------------------------------------------

PATHS: list[tuple[str, dict[str, str], tuple[str, ...], list[str]]] = [
    (
        "linux without avx2",
        {"arch": "amd64", "cpu_level": "compat-only"},
        CPU[:1],
        ["polars-compat-runtime", "x86-host-with-features", "arm64-host", "ci-runner"],
    ),
    (
        "linux without sse4.2",
        {"arch": "amd64", "cpu_level": "below-compat"},
        CPU[:1],
        ["x86-host-with-features", "arm64-host", "ci-runner"],
    ),
    (
        "linux without sse4.2, the compatibility runtime",
        {"arch": "amd64", "cpu_level": "below-compat", "polars_runtime": "compat"},
        CPU_COMPAT[:1],
        ["x86-host-with-features", "arm64-host", "ci-runner"],
    ),
    (
        "macos under rosetta",
        {**MACOS, "arch": "amd64", "translation": "rosetta"},
        ROSETTA[:1],
        ["native-arm64"],
    ),
    (
        "windows, x64 python on arm64",
        {**WINDOWS, "arch": "amd64", "translation": "x64-on-arm64"},
        X64_ON_ARM64[:1],
        ["native-arm64", "wsl2"],
    ),
    (
        "python outside the range, on linux",
        {"python_in_range": "no"},
        PYTHON[:1],
        ["supported-python", "container-image", "ci-runner"],
    ),
    (
        "python outside the range, on windows",
        {**WINDOWS, "python_in_range": "no"},
        PYTHON[:1],
        ["supported-python", "container-image", "ci-runner"],
    ),
    (
        "python outside the range, on another system",
        {"os": "other", "host_os": "other", "python_in_range": "no"},
        PYTHON[:1],
        ["supported-python", "ci-runner"],
    ),
    (
        "freebsd",
        {"os": "other", "host_os": "other"},
        OTHER_OS[:1],
        ["linux-or-macos-host", "ci-runner"],
    ),
    (
        "linux on another processor",
        {"arch": "other"},
        OTHER_ARCH[:1],
        ["x86-host-with-features", "arm64-host", "ci-runner"],
    ),
    (
        "nix mode on windows",
        {**WINDOWS, "run_mode": "nix"},
        NIX[:1],
        ["wsl2", "container-image", "mode-local"],
    ),
    (
        "container mode with a sandbox, on linux",
        {"run_mode": "container", "sandbox_mode": "auto"},
        IN_CONTAINER[:1],
        ["mode-local-sandboxed"],
    ),
    (
        "container mode with a sandbox, on macos",
        {**MACOS, "run_mode": "container", "sandbox_mode": "auto"},
        IN_CONTAINER[:1],
        ["mode-local-sandboxed"],
    ),
    (
        "container mode with a sandbox, on windows",
        {**WINDOWS, "run_mode": "container", "sandbox_mode": "auto"},
        IN_CONTAINER[:1],
        ["wsl2-sandboxed"],
    ),
    (
        "container mode with a sandbox, on windows, the image's linux and no backend",
        {
            **WINDOWS_IMAGE,
            "run_mode": "container",
            "sandbox_mode": "auto",
            "sandbox_backend": "none",
        },
        IN_CONTAINER[:1],
        ["wsl2-sandboxed"],
    ),
    (
        "no sandbox backend on linux",
        {"sandbox_mode": "auto", "sandbox_backend": "none"},
        NO_BACKEND_AUTO[:1],
        ["install-bubblewrap", "sandbox-capable-host"],
    ),
    (
        "no sandbox backend on windows",
        {**WINDOWS, "sandbox_mode": "auto", "sandbox_backend": "none"},
        NO_BACKEND_AUTO[:1],
        ["wsl2-sandboxed", "sandbox-capable-host"],
    ),
    (
        "no sandbox backend on macos",
        {**MACOS, "sandbox_mode": "named", "sandbox_backend": "none"},
        NO_BACKEND_NAMED[:1],
        ["sandbox-capable-host"],
    ),
    (
        "landlock abi 5",
        {
            "sandbox_mode": "auto",
            "sandbox_backend": "landlock",
            "sandbox_loss": "landlock-below-6",
        },
        LANDLOCK[:1],
        ["newer-kernel-landlock", "install-bubblewrap"],
    ),
    (
        "bubblewrap without the cache overlay",
        {
            "sandbox_mode": "auto",
            "sandbox_backend": "bwrap",
            "sandbox_loss": "caches-read-only",
        },
        BWRAP_CACHES[:1],
        ["newer-bubblewrap"],
    ),
    (
        "express on windows",
        {**WINDOWS, "express_requested": "yes"},
        EXPRESS[:1],
        ["wsl2", "linux-or-macos-host"],
    ),
    (
        "the powershell 5.1 wrapper",
        {**WINDOWS, "shell": "powershell-5"},
        POWERSHELL_5[:1],
        ["pwsh7"],
    ),
    (
        "the git bash wrapper",
        {**WINDOWS, "shell": "msys-wrapper"},
        MSYS[:1],
        ["pwsh7", "wsl2"],
    ),
    (
        "an image of another architecture",
        {"run_mode": "container", "image_arch_matches": "no"},
        IMAGE_ARCH[:1],
        ["native-image"],
    ),
]


@pytest.mark.parametrize(
    ("overlay", "row", "expected"),
    [pytest.param(o, r[0], e, id=name) for name, o, r, e in PATHS],
)
def test_a_configuration_is_offered_these_ways_out_in_this_order(
    overlay: dict[str, str], row: str, expected: list[str]
) -> None:
    assert _offered(_facts(**overlay), row) == expected


def test_the_container_image_is_offered_nowhere_for_a_missing_instruction_set() -> None:
    for level in ["compat-only", "below-compat"]:
        for host in [{}, MACOS, WINDOWS]:
            facts = _facts(arch="amd64", cpu_level=level, **host)
            cpu_rows = [
                e for e in sr.evaluate(facts, "ash") if e.row.dimension == "cpu"
            ]
            assert cpu_rows, (level, host)
            for found in cpu_rows:
                assert "container-image" not in [p.id for p in found.paths], (
                    found.row.id
                )


def test_only_the_paths_the_cli_spells_as_a_command_name_a_builder() -> None:
    builders = {p.id: p.command_builder for p in sr.REGISTER.paths if p.command_builder}
    assert builders == {
        "polars-compat-runtime": "polars-compat-runtime",
        "container-image": "container-image",
        "native-image": "native-image",
        "mode-local": "mode-local",
        "mode-local-sandboxed": "mode-local-sandboxed",
    }
    assert "rtcompat" in sr.REGISTER.path("polars-compat-runtime").summary


# ---------------------------------------------------------------------------
# Windows, local: nothing at start, the skips at their decisions
# ---------------------------------------------------------------------------


def test_windows_amd64_local_raises_nothing_at_start_and_two_skips_at_decisions() -> (
    None
):
    facts = _facts(**WINDOWS, arch="amd64")
    assert sr.evaluate(facts, "ash", notify=sr.Notify.START) == ()
    assert sr.evaluate(facts, "ash", notify=sr.Notify.DECISION) == ()
    assert _raised(facts, "semgrep") == [
        ("scanner.semgrep.windows", "unsupported", "skips-scanner")
    ]
    assert _raised(facts, "guarddog") == [
        ("scanner.guarddog.windows", "unsupported", "skips-scanner")
    ]
    assert _raised(facts, "bandit") == []


def test_the_matrix_only_windows_rows_are_never_raised() -> None:
    facts = _facts(**WINDOWS, arch="amd64")
    matrix = [e.row.id for e in sr.evaluate(facts, "ash", notify=sr.Notify.MATRIX)]
    assert matrix == [
        "host.windows.no-graceful-stop",
        "host.windows.no-tool-database-lock",
    ]
    assert [e.row.id for e in sr.evaluate(facts, "snyk-code")] == [
        "scanner.snyk-code.windows-leftovers"
    ]
    assert _raised(facts, "snyk-code") == []


def test_windows_container_mode_meets_the_container_limit_and_not_the_windows_ones() -> (
    None
):
    container = _facts(os="linux", host_os="windows", run_mode="container")
    found = [e.row.id for e in sr.evaluate(container, "ash")]
    assert found == ["host.windows.container-leftovers"]
    assert sr.evaluate(container, "ash", notify=sr.Notify.START) == ()
    assert sr.evaluate(container, "semgrep") == ()


# ---------------------------------------------------------------------------
# The scanner rows that need a fact only the decision knows
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scanner", IGNORE_PATHS_TOOLS)
def test_ignore_paths_are_not_passed_to_four_tools_on_windows(scanner: str) -> None:
    facts = _facts(**WINDOWS, ignore_paths="set")
    (found,) = sr.evaluate(facts, scanner)
    assert found.row.id == f"scanner.{scanner}.windows-ignore-paths"
    assert found.row.level is sr.SupportLevel.DEGRADED
    assert found.row.dimension == "ignore paths"
    assert scanner in (found.row.lost or "")
    assert "suppresses their findings" in (found.row.lost or "")
    assert [p.id for p in found.paths] == ["wsl2", "container-image"]
    assert _raised(_facts(**WINDOWS, ignore_paths="none"), scanner) == []
    assert _raised(_facts(ignore_paths="set"), scanner) == []


@pytest.mark.parametrize("scanner", IGNORE_PATHS_TOOLS)
def test_ignore_paths_limit_applies_in_local_and_pre_commit_modes_only(
    scanner: str,
) -> None:
    """On Windows in container mode the scanners run in Linux and get the ignore
    paths, so the row is not raised there, nor in Nix mode, which Windows refuses."""
    row = _ignore_paths(scanner)
    for mode in ("local", "precommit"):
        facts = _facts(**WINDOWS, ignore_paths="set", run_mode=mode)
        assert _raised(facts, scanner) == [row], mode
    for mode in ("container", "nix"):
        facts = _facts(**WINDOWS, ignore_paths="set", run_mode=mode)
        assert _raised(facts, scanner) == [], mode


def test_guarddog_without_its_kernel_sandbox_is_degraded_and_always_shown() -> None:
    facts = _facts(tool_sandbox="unavailable")
    (found,) = sr.evaluate(facts, "guarddog")
    assert found.row.id == "scanner.guarddog.sandbox-unavailable"
    assert found.row.level is sr.SupportLevel.DEGRADED
    assert found.row.cli_on_stderr
    assert [p.id for p in found.paths] == ["enable-landlock"]


def test_guarddog_without_its_kernel_sandbox_is_never_raised_without_a_way_out() -> (
    None
):
    """GuardDog's own sandbox is unavailable only where Landlock is, and the one way
    out is a Linux kernel setting, so a Mac run raises nothing here: a row that a
    run raises always has a way out on the machine that raises it."""
    others = {"os": "other", "host_os": "other"}
    for host in ({}, MACOS, WINDOWS, others):
        facts = _facts(**host, tool_sandbox="unavailable")
        raised = sr.evaluate(
            facts, "guarddog", notify=(sr.Notify.START, sr.Notify.DECISION)
        )
        for found in raised:
            assert found.paths, (host, found.row.id)
    assert _raised(_facts(**MACOS, tool_sandbox="unavailable"), "guarddog") == []


def test_guarddog_under_sandbox_exec_and_betterleaks_are_polyfilled() -> None:
    facts = _facts(
        **MACOS,
        arch="arm64",
        sandbox_mode="auto",
        sandbox_backend="sandbox-exec",
        tool_sandbox="replaced",
    )
    assert _raised(facts, "guarddog") == [
        ("scanner.guarddog.sandbox-replaced", "polyfilled", "continues")
    ]
    assert _raised(facts, "betterleaks") == [
        ("scanner.betterleaks.private-home", "polyfilled", "continues")
    ]
    assert (
        _raised(_facts(sandbox_mode="auto", sandbox_backend="bwrap"), "betterleaks")
        == []
    )


def test_guarddog_under_ashs_sandbox_is_polyfilled_only_where_ash_sandboxes_it() -> (
    None
):
    """The stand-in is ASH's sandbox-exec confinement, so the row needs macOS, a
    sandbox asked for and sandbox-exec as the backend, as the Betterleaks row does.
    Without them no run has the stand-in, and a matrix cell must not show it."""
    on_mac = {**MACOS_SANDBOXED, "tool_sandbox": "replaced"}
    assert _raised(_facts(**on_mac), "guarddog") == [GUARDDOG_REPLACED]
    elsewhere = {
        "the sandbox off": {"sandbox_mode": "off"},
        "linux": {"os": "linux", "host_os": "linux"},
        "another backend": {"sandbox_backend": "bwrap"},
    }
    for name, change in elsewhere.items():
        assert _raised(_facts(**{**on_mac, **change}), "guarddog") == [], name
    assert sr.cells("guarddog", {"tool_sandbox": "replaced"}) == "yes"


# ---------------------------------------------------------------------------
# Windows arm64: the derived rows, from the shipped scanners' own platforms
# ---------------------------------------------------------------------------


@functools.cache
def _universe() -> tuple[type, ...]:
    classes, _errors = load_scanner_universe()
    return tuple(classes)


def _pinned_binaries() -> list[sr.PinnedBinary]:
    return pinned_binaries(_universe())


def _missing_builds(
    register: sr.Register, binaries: list[sr.PinnedBinary], facts: sr.HostFacts
) -> dict[str, sr.Evaluation]:
    """The missing-build row each pinned scanner raises on ``facts``. A scanner's
    other rows are other limits of the same configuration, so they are not read as a
    missing build, and one scanner has at most one missing-build row there."""
    missing = {}
    for binary in binaries:
        derived = [
            found
            for found in register.evaluate(facts, binary.scanner)
            if found.row.anchor == sr.NO_BUILD_ANCHOR
        ]
        if derived:
            (only,) = derived
            missing[binary.scanner] = only
    return missing


def test_windows_arm64_raises_a_missing_build_for_each_tool_without_one() -> None:
    planted = sr.PinnedBinary(
        scanner="planted",
        tool="plantedtool",
        version="0.0.1",
        provisionable=("linux/amd64",),
    )
    binaries = [*_pinned_binaries(), planted]
    register = sr.REGISTER.extended(rows=sr.no_build_rows(binaries))
    facts = _facts(**WINDOWS, arch="arm64")
    missing = _missing_builds(register, binaries, facts)
    lacking = sorted(
        binary.scanner
        for binary in binaries
        if binary.provisionable and "windows/arm64" not in binary.provisionable
    )
    assert "planted" in lacking, "the planted tool has no windows/arm64 build"
    assert sorted(missing) == lacking
    for scanner, found in missing.items():
        binary = next(b for b in binaries if b.scanner == scanner)
        assert found.row.behavior is sr.Behavior.SCANNER_MISSING
        assert found.row.level is sr.SupportLevel.UNSUPPORTED
        assert found.row.notify is sr.Notify.DECISION
        assert found.row.reason == (
            f"ASH has no {binary.tool} {binary.version} build for windows/arm64."
        )
        assert [p.id for p in found.paths] == [
            "wsl2",
            "container-image",
            "linux-or-macos-host",
        ]


def test_a_row_that_is_not_a_missing_build_is_not_read_as_one() -> None:
    """The must-fail control for the reading above: a pinned scanner that gains
    another Windows row still has exactly one missing-build row."""
    binaries = _pinned_binaries()
    scanner = next(
        b.scanner
        for b in binaries
        if b.provisionable and "windows/arm64" not in b.provisionable
    )
    other = sr.SupportRow(
        id=f"scanner.{scanner}.windows-other-limit",
        scope=scanner,
        dimension="os",
        match=sr.Match(os=("windows",)),
        level=sr.SupportLevel.DEGRADED,
        behavior=sr.Behavior.CONTINUES,
        notify=sr.Notify.MATRIX,
        reason="Another limit of this scanner on Windows.",
        cell="another limit on Windows",
        lost="A function of this scanner is lost on Windows.",
        paths=("wsl2", "container-image"),
    )
    register = sr.REGISTER.extended(rows=(*sr.no_build_rows(binaries), other))
    facts = _facts(**WINDOWS, arch="arm64")
    assert len(register.evaluate(facts, scanner)) == 2, "the other row matches too"
    missing = _missing_builds(register, binaries, facts)
    assert missing[scanner].row.anchor == sr.NO_BUILD_ANCHOR
    assert missing[scanner].row.id.startswith(f"scanner.{scanner}.no-build.")
    assert missing == _missing_builds(
        sr.REGISTER.extended(rows=sr.no_build_rows(binaries)), binaries, facts
    )


def test_no_other_platform_and_no_other_tool_has_a_missing_build_row() -> None:
    binaries = _pinned_binaries()
    assert binaries, "the scanner universe holds no pinned binary"
    wanted = {
        (binary.scanner, pair)
        for binary in binaries
        if binary.provisionable
        for pair in sr.ALL_PLATFORMS
        if pair not in binary.provisionable
    }
    found = {
        (row.scope, row.id.rpartition(".")[2].replace("-", "/", 1))
        for row in sr.no_build_rows(binaries)
    }
    assert found == wanted
    assert unallowed_gap_rows(sr.no_build_rows(binaries)) == [], UNALLOWED_GAP


def _planted_lacking(platform: str) -> sr.PinnedBinary:
    """A pinned binary with a build for every platform but ``platform``."""
    return sr.PinnedBinary(
        scanner="planted",
        tool="plantedtool",
        version="0.0.1",
        provisionable=all_platforms_but(platform),
    )


def test_a_scanner_that_loses_windows_amd64_fails_the_missing_build_row_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The must-fail control for the test above, run on the test itself: the rows still
    match the declaration they come from, so only the allowed platforms report a scanner
    that has lost windows/amd64. The same scanner lacking only windows/arm64 passes."""
    loses_amd64 = _planted_lacking("windows/amd64")
    monkeypatch.setitem(globals(), "_pinned_binaries", lambda: [loses_amd64])
    with pytest.raises(AssertionError, match="outside ALLOWED_GAP_PLATFORMS"):
        test_no_other_platform_and_no_other_tool_has_a_missing_build_row()
    loses_arm64 = _planted_lacking("windows/arm64")
    monkeypatch.setitem(globals(), "_pinned_binaries", lambda: [loses_arm64])
    test_no_other_platform_and_no_other_tool_has_a_missing_build_row()


def test_the_derived_rows_follow_the_scanners_platform_declaration() -> None:
    """A tool whose declaration gains a platform loses that platform's row."""
    binaries = _pinned_binaries()
    grype = next(b for b in binaries if b.scanner == "grype")
    assert "windows/arm64" not in grype.provisionable
    widened = replace(grype, provisionable=sr.ALL_PLATFORMS)
    assert sr.no_build_rows((widened,)) == ()


# ---------------------------------------------------------------------------
# What is declared, pinned as a table
# ---------------------------------------------------------------------------

_HERE = ("wsl2", "container-image", "linux-or-macos-host")
_CPU_PATHS = (
    "polars-compat-runtime",
    "native-arm64",
    "x86-host-with-features",
    "arm64-host",
    "ci-runner",
)
#: The processor row for a processor below the compatibility runtime's own set leaves
#: out the compatibility runtime, which is already in use there and cannot help.
_BELOW_COMPAT_PATHS = (
    "native-arm64",
    "x86-host-with-features",
    "arm64-host",
    "ci-runner",
)
_SANDBOX_PATHS = ("install-bubblewrap", "wsl2-sandboxed", "sandbox-capable-host")

# (id, level, behavior, notify, dimension, shown on stderr, paths)
DECLARED: list[tuple[str, str, str, str, str, bool, tuple[str, ...]]] = [
    (
        "host.cpu.below-polars-runtime",
        "unsupported",
        "continues",
        "start",
        "cpu",
        True,
        _CPU_PATHS,
    ),
    (
        "host.cpu.below-polars-compat",
        "unsupported",
        "continues",
        "start",
        "cpu",
        True,
        _BELOW_COMPAT_PATHS,
    ),
    (
        "host.cpu.polars-compat-runtime",
        "polyfilled",
        "continues",
        "start",
        "cpu",
        False,
        (),
    ),
    (
        "host.translation.rosetta",
        "degraded",
        "continues",
        "start",
        "translation",
        True,
        ("native-arm64",),
    ),
    (
        "host.translation.x64-on-arm64",
        "degraded",
        "continues",
        "start",
        "translation",
        True,
        ("native-arm64", "wsl2"),
    ),
    (
        "host.os.other",
        "unsupported",
        "continues",
        "start",
        "os",
        True,
        ("linux-or-macos-host", "ci-runner"),
    ),
    (
        "host.arch.other",
        "unsupported",
        "continues",
        "start",
        "arch",
        True,
        ("x86-host-with-features", "arm64-host", "ci-runner"),
    ),
    (
        "host.python.outside-requires",
        "unsupported",
        "continues",
        "start",
        "python",
        True,
        ("supported-python", "container-image", "ci-runner"),
    ),
    (
        "host.mode.nix-on-windows",
        "unsupported",
        "refuses",
        "start",
        "run mode",
        True,
        ("wsl2", "container-image", "mode-local"),
    ),
    (
        "host.sandbox.not-applied-in-container",
        "degraded",
        "continues",
        "start",
        "sandbox",
        True,
        ("mode-local-sandboxed", "wsl2-sandboxed"),
    ),
    (
        "host.sandbox.unavailable-auto",
        "unsupported",
        "scanner-missing",
        "decision",
        "sandbox",
        True,
        _SANDBOX_PATHS,
    ),
    (
        "host.sandbox.unavailable-named",
        "unsupported",
        "scanner-error",
        "decision",
        "sandbox",
        True,
        _SANDBOX_PATHS,
    ),
    (
        "host.sandbox.landlock-below-6",
        "degraded",
        "continues",
        "decision",
        "sandbox",
        False,
        ("newer-kernel-landlock", "install-bubblewrap"),
    ),
    (
        "host.sandbox.bwrap-caches-read-only",
        "degraded",
        "continues",
        "decision",
        "sandbox",
        False,
        ("newer-bubblewrap",),
    ),
    (
        "host.express.unavailable",
        "degraded",
        "continues",
        "start",
        "express",
        True,
        ("wsl2", "linux-or-macos-host"),
    ),
    (
        "host.windows.no-graceful-stop",
        "degraded",
        "continues",
        "matrix",
        "os",
        False,
        _HERE,
    ),
    (
        "host.windows.no-tool-database-lock",
        "degraded",
        "continues",
        "matrix",
        "os",
        False,
        ("wsl2", "container-image"),
    ),
    (
        "host.windows.container-leftovers",
        "degraded",
        "continues",
        "matrix",
        "container leftovers",
        False,
        ("wsl2",),
    ),
    (
        "host.shell.powershell-5",
        "polyfilled",
        "continues",
        "start",
        "shell",
        False,
        ("pwsh7",),
    ),
    (
        "host.shell.msys",
        "polyfilled",
        "continues",
        "start",
        "shell",
        False,
        ("pwsh7", "wsl2"),
    ),
    (
        "host.container.image-arch-mismatch",
        "degraded",
        "continues",
        "decision",
        "container image",
        True,
        ("native-image",),
    ),
    (
        "scanner.semgrep.windows",
        "unsupported",
        "skips-scanner",
        "decision",
        "os",
        True,
        _HERE,
    ),
    (
        "scanner.guarddog.windows",
        "unsupported",
        "skips-scanner",
        "decision",
        "os",
        True,
        _HERE,
    ),
    (
        "scanner.guarddog.sandbox-replaced",
        "polyfilled",
        "continues",
        "decision",
        "tool sandbox",
        False,
        (),
    ),
    (
        "scanner.guarddog.sandbox-unavailable",
        "degraded",
        "continues",
        "decision",
        "tool sandbox",
        True,
        ("enable-landlock",),
    ),
    (
        "scanner.betterleaks.private-home",
        "polyfilled",
        "continues",
        "decision",
        "sandbox",
        False,
        (),
    ),
    (
        "scanner.trivy.windows-ignore-paths",
        "degraded",
        "continues",
        "decision",
        "ignore paths",
        False,
        ("wsl2", "container-image"),
    ),
    (
        "scanner.trivy-repo.windows-ignore-paths",
        "degraded",
        "continues",
        "decision",
        "ignore paths",
        False,
        ("wsl2", "container-image"),
    ),
    (
        "scanner.checkov.windows-ignore-paths",
        "degraded",
        "continues",
        "decision",
        "ignore paths",
        False,
        ("wsl2", "container-image"),
    ),
    (
        "scanner.ferret-scan.windows-ignore-paths",
        "degraded",
        "continues",
        "decision",
        "ignore paths",
        False,
        ("wsl2", "container-image"),
    ),
    (
        "scanner.snyk-code.windows-leftovers",
        "degraded",
        "continues",
        "matrix",
        "os",
        False,
        ("wsl2", "container-image"),
    ),
]


def test_the_register_declares_exactly_these_rows_in_this_order() -> None:
    actual = [
        (
            row.id,
            row.level.value,
            row.behavior.value,
            row.notify.value,
            row.dimension,
            row.cli_on_stderr,
            row.paths,
        )
        for row in sr.REGISTER.rows
        if row.level is not sr.SupportLevel.SUPPORTED
    ]
    assert actual == DECLARED


def test_only_the_express_row_leaves_the_results_alone() -> None:
    quiet = [row.id for row in sr.REGISTER.rows if not row.results]
    assert quiet == ["host.express.unavailable"]


_ADAPTATIONS = {
    "windows-executable-lookup": "windows",
    "windows-command-line-bounds": "windows",
    "windows-console-rendering": "windows",
    "windows-atomic-replace-retry": "windows",
    "windows-output-decoding": "windows",
    "windows-link-open-check": "windows",
    "macos-process-wait": "darwin",
    "macos-quarantine-removal": "darwin",
    "linux-fork-start": "linux",
}


def test_an_adaptation_is_a_supported_row_that_raises_nothing() -> None:
    rows = [r for r in sr.REGISTER.rows if r.level is sr.SupportLevel.SUPPORTED]
    assert sorted(r.polyfill or "" for r in rows) == sorted(_ADAPTATIONS)
    for row in rows:
        assert row.id == f"host.adaptation.{row.polyfill}"
        assert row.behavior is sr.Behavior.CONTINUES
        assert row.notify is sr.Notify.MATRIX
        assert row.paths == ()
        assert not row.match.is_empty()
        polyfill = sr.REGISTER.polyfill(row.polyfill or "")
        assert polyfill.kind is sr.PolyfillKind.ADAPTATION
        assert polyfill.difference is None
        os_tokens = row.match.os or row.match.host_os
        assert os_tokens == (_ADAPTATIONS[polyfill.id],), polyfill.id


def test_the_five_stand_ins_say_what_a_user_can_see() -> None:
    kinds = {
        p.id: p.kind
        for p in sr.REGISTER.polyfills
        if p.kind is not sr.PolyfillKind.ADAPTATION
    }
    assert kinds == {
        "polars-compat-runtime": sr.PolyfillKind.SUBSTITUTE,
        "powershell-5-compat": sr.PolyfillKind.SUBSTITUTE,
        "msys-path-rules": sr.PolyfillKind.SUBSTITUTE,
        "guarddog-ash-sandbox": sr.PolyfillKind.SUBSTITUTE,
        "betterleaks-private-home": sr.PolyfillKind.SUBSTITUTE,
    }
    for polyfill in sr.REGISTER.polyfills:
        if polyfill.kind is not sr.PolyfillKind.ADAPTATION:
            assert polyfill.difference, polyfill.id


# ---------------------------------------------------------------------------
# The defaults the register states: what it does not do
# ---------------------------------------------------------------------------


def test_a_processor_without_the_instructions_is_declared_to_continue() -> None:
    for row_id in ["host.cpu.below-polars-runtime", "host.cpu.below-polars-compat"]:
        assert sr.REGISTER.row(row_id).behavior is sr.Behavior.CONTINUES


def test_a_translated_run_is_degraded_and_not_unsupported() -> None:
    for row_id in ["host.translation.rosetta", "host.translation.x64-on-arm64"]:
        assert sr.REGISTER.row(row_id).level is sr.SupportLevel.DEGRADED


def test_another_operating_system_or_processor_is_declared_to_continue() -> None:
    for row_id in ["host.os.other", "host.arch.other"]:
        assert sr.REGISTER.row(row_id).behavior is sr.Behavior.CONTINUES


def test_musl_is_not_declared_and_not_unsupported() -> None:
    assert ("libc", "musl") in sr.REGISTER.not_declared
    assert sr.evaluate(_facts(libc="musl"), "ash") == ()


def test_a_way_out_on_another_machine_names_only_machines_ash_runs_on_in_ci() -> None:
    allowed = {"LINUX_AMD64", "LINUX_ARM64", "MACOS_ARM64"}
    for path in sr.REGISTER.paths:
        if path.kind.here:
            continue
        targets = {path.target} if isinstance(path.target, str) else set(path.target)
        assert targets <= allowed, (path.id, targets)


def test_a_non_ascii_character_appears_in_no_sentence_the_register_holds() -> None:
    def sentences() -> Any:
        for row in sr.REGISTER.rows:
            yield row.id, (row.reason, row.cell, row.lost or "")
        for path in sr.REGISTER.paths:
            yield path.id, (path.summary,)
        for polyfill in sr.REGISTER.polyfills:
            yield (
                polyfill.id,
                (
                    polyfill.name,
                    polyfill.cell,
                    polyfill.stands_in_for,
                    polyfill.difference or "",
                ),
            )
        for key, reason in sr.REGISTER.not_declared.items():
            yield str(key), (reason,)

    count = 0
    for owner, texts in sentences():
        for text in texts:
            count += 1
            assert text.isascii(), (owner, text)
    assert count > 150, count
