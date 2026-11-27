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

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base import support_register as sr
from automated_security_helper.utils import tool_downloads
from tests.utils.scanner_enumeration import load_scanner_universe

pytestmark = pytest.mark.unit


def _facts(**overlay: str) -> sr.HostFacts:
    """The reference facts with ``overlay`` on them, settled as a run's are."""
    return sr.settle(replace(sr.REFERENCE_FACTS, **overlay))


def _raised(
    facts: sr.HostFacts, scope: str = "ash"
) -> list[tuple[str, str, str]]:
    """The rows a run raises, at start or at a decision, worst first."""
    found = sr.evaluate(facts, scope, notify=(sr.Notify.START, sr.Notify.DECISION))
    return [(e.row.id, e.row.level.value, e.row.behavior.value) for e in found]


def _offered(
    facts: sr.HostFacts, row_id: str, scope: str = "ash"
) -> list[str] | None:
    """The ids of the paths offered for ``row_id`` on ``facts``, or None when the
    row does not match."""
    for found in sr.evaluate(facts, scope):
        if found.row.id == row_id:
            return [path.id for path in found.paths]
    return None


WINDOWS = {"os": "windows", "host_os": "windows", "express_available": "no"}
MACOS = {"os": "darwin", "host_os": "darwin"}

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
    ("express asked for on windows", {**WINDOWS, "express_requested": "yes"}, [EXPRESS]),
    ("nix mode on windows", {**WINDOWS, "run_mode": "nix"}, [NIX]),
    ("the powershell 5.1 wrapper", {**WINDOWS, "shell": "powershell-5"}, [POWERSHELL_5]),
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


def test_the_cases_cover_every_row_a_run_can_raise_in_the_ash_scope() -> None:
    """A row no case raises is a row nothing here holds."""
    seen = {row[0] for _, _, rows in CASES for row in rows}
    declared = {
        row.id
        for row in sr.REGISTER.rows
        if row.scope == "ash" and row.notify is not sr.Notify.MATRIX
    }
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
            cpu_rows = [e for e in sr.evaluate(facts, "ash") if e.row.dimension == "cpu"]
            assert cpu_rows, (level, host)
            for found in cpu_rows:
                assert "container-image" not in [p.id for p in found.paths], found.row.id


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
# Windows, local: no notice at start, the skips at their decisions
# ---------------------------------------------------------------------------


def test_windows_amd64_local_raises_nothing_at_start_and_two_skips_at_decisions() -> None:
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


def test_windows_container_mode_meets_the_container_limit_and_not_the_windows_ones() -> None:
    container = _facts(os="linux", host_os="windows", run_mode="container")
    found = [e.row.id for e in sr.evaluate(container, "ash")]
    assert found == ["host.windows.container-leftovers"]
    assert sr.evaluate(container, "ash", notify=sr.Notify.START) == ()
    assert sr.evaluate(container, "semgrep") == ()


# ---------------------------------------------------------------------------
# The scanner rows that need a fact only the decision knows
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scanner", ["trivy", "trivy-repo", "checkov", "ferret-scan"])
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


def test_guarddog_without_its_kernel_sandbox_is_degraded_and_always_shown() -> None:
    facts = _facts(tool_sandbox="unavailable")
    (found,) = sr.evaluate(facts, "guarddog")
    assert found.row.id == "scanner.guarddog.sandbox-unavailable"
    assert found.row.level is sr.SupportLevel.DEGRADED
    assert found.row.cli_on_stderr
    assert [p.id for p in found.paths] == ["enable-landlock"]
    assert _raised(_facts(**MACOS, tool_sandbox="unavailable"), "guarddog") == [
        ("scanner.guarddog.sandbox-unavailable", "degraded", "continues")
    ]


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
    assert _raised(_facts(sandbox_mode="auto", sandbox_backend="bwrap"), "betterleaks") == []


# ---------------------------------------------------------------------------
# Windows arm64: the derived rows, from the shipped scanners' own platforms
# ---------------------------------------------------------------------------


@functools.cache
def _universe() -> tuple[type, ...]:
    classes, _errors = load_scanner_universe()
    return tuple(classes)


def _pinned_binaries() -> list[sr.PinnedBinary]:
    found = []
    for cls in _universe():
        facets: opsf.ScannerOperationalFacets = vars(cls)[opsf.OPERATIONAL_FACETS_ATTR]
        if facets.runtime.kind is not opsf.RuntimeKind.PINNED_BINARY:
            continue
        key = facets.runtime.tool_versions_key
        assert key is not None, facets.scanner_name
        found.append(
            sr.PinnedBinary(
                scanner=facets.scanner_name,
                tool=key,
                version=tool_downloads.TOOL_VERSIONS[key],
                provisionable=facets.platforms.provisionable,
            )
        )
    return found


def test_windows_arm64_native_raises_a_missing_build_for_five_tools() -> None:
    binaries = _pinned_binaries()
    register = sr.REGISTER.extended(rows=sr.no_build_rows(binaries))
    facts = _facts(**WINDOWS, arch="arm64")
    missing = {}
    for binary in binaries:
        found = register.evaluate(facts, binary.scanner)
        if found:
            (only,) = found
            missing[binary.scanner] = only
    assert sorted(missing) == ["grype", "hadolint", "opengrep", "trivy", "trivy-repo"]
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


def test_no_other_platform_and_no_other_tool_has_a_missing_build_row() -> None:
    rows = sr.no_build_rows(_pinned_binaries())
    assert len(rows) == 5
    assert {row.id.rpartition(".")[2] for row in rows} == {"windows-arm64"}


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
_SANDBOX_PATHS = ("install-bubblewrap", "wsl2-sandboxed", "sandbox-capable-host")

# (id, level, behavior, notify, dimension, shown on stderr, paths)
DECLARED: list[tuple[str, str, str, str, str, bool, tuple[str, ...]]] = [
    ("host.cpu.below-polars-runtime", "unsupported", "continues", "start", "cpu", True, _CPU_PATHS),
    ("host.cpu.below-polars-compat", "unsupported", "continues", "start", "cpu", True, _CPU_PATHS),
    ("host.cpu.polars-compat-runtime", "polyfilled", "continues", "start", "cpu", False, ()),
    ("host.translation.rosetta", "degraded", "continues", "start", "translation", True, ("native-arm64",)),
    ("host.translation.x64-on-arm64", "degraded", "continues", "start", "translation", True, ("native-arm64", "wsl2")),
    ("host.os.other", "unsupported", "continues", "start", "os", True, ("linux-or-macos-host", "ci-runner")),
    ("host.arch.other", "unsupported", "continues", "start", "arch", True, ("x86-host-with-features", "arm64-host", "ci-runner")),
    ("host.python.outside-requires", "unsupported", "continues", "start", "python", True, ("supported-python", "container-image", "ci-runner")),
    ("host.mode.nix-on-windows", "unsupported", "refuses", "start", "run mode", True, ("wsl2", "container-image", "mode-local")),
    ("host.sandbox.not-applied-in-container", "degraded", "continues", "start", "sandbox", True, ("mode-local-sandboxed", "wsl2-sandboxed")),
    ("host.sandbox.unavailable-auto", "unsupported", "scanner-missing", "decision", "sandbox", True, _SANDBOX_PATHS),
    ("host.sandbox.unavailable-named", "unsupported", "scanner-error", "decision", "sandbox", True, _SANDBOX_PATHS),
    ("host.sandbox.landlock-below-6", "degraded", "continues", "decision", "sandbox", False, ("newer-kernel-landlock", "install-bubblewrap")),
    ("host.sandbox.bwrap-caches-read-only", "degraded", "continues", "decision", "sandbox", False, ("newer-bubblewrap",)),
    ("host.express.unavailable", "degraded", "continues", "start", "express", True, ("wsl2", "linux-or-macos-host")),
    ("host.windows.no-graceful-stop", "degraded", "continues", "matrix", "os", False, _HERE),
    ("host.windows.no-tool-database-lock", "degraded", "continues", "matrix", "os", False, ("wsl2", "container-image")),
    ("host.windows.container-leftovers", "degraded", "continues", "matrix", "container leftovers", False, ("wsl2",)),
    ("host.shell.powershell-5", "polyfilled", "continues", "start", "shell", False, ("pwsh7",)),
    ("host.shell.msys", "polyfilled", "continues", "start", "shell", False, ("pwsh7", "wsl2")),
    ("host.container.image-arch-mismatch", "degraded", "continues", "decision", "container image", True, ("native-image",)),
    ("scanner.semgrep.windows", "unsupported", "skips-scanner", "decision", "os", True, _HERE),
    ("scanner.guarddog.windows", "unsupported", "skips-scanner", "decision", "os", True, _HERE),
    ("scanner.guarddog.sandbox-replaced", "polyfilled", "continues", "decision", "tool sandbox", False, ()),
    ("scanner.guarddog.sandbox-unavailable", "degraded", "continues", "decision", "tool sandbox", True, ("enable-landlock",)),
    ("scanner.betterleaks.private-home", "polyfilled", "continues", "decision", "sandbox", False, ()),
    ("scanner.trivy.windows-ignore-paths", "degraded", "continues", "decision", "ignore paths", False, ("wsl2", "container-image")),
    ("scanner.trivy-repo.windows-ignore-paths", "degraded", "continues", "decision", "ignore paths", False, ("wsl2", "container-image")),
    ("scanner.checkov.windows-ignore-paths", "degraded", "continues", "decision", "ignore paths", False, ("wsl2", "container-image")),
    ("scanner.ferret-scan.windows-ignore-paths", "degraded", "continues", "decision", "ignore paths", False, ("wsl2", "container-image")),
    ("scanner.snyk-code.windows-leftovers", "degraded", "continues", "matrix", "os", False, ("wsl2", "container-image")),
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


def test_a_processor_without_the_instructions_continues_after_the_notice() -> None:
    for row_id in ["host.cpu.below-polars-runtime", "host.cpu.below-polars-compat"]:
        assert sr.REGISTER.row(row_id).behavior is sr.Behavior.CONTINUES


def test_a_translated_run_is_degraded_and_not_unsupported() -> None:
    for row_id in ["host.translation.rosetta", "host.translation.x64-on-arm64"]:
        assert sr.REGISTER.row(row_id).level is sr.SupportLevel.DEGRADED


def test_another_operating_system_or_processor_continues_after_the_notice() -> None:
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
            yield polyfill.id, (
                polyfill.name,
                polyfill.cell,
                polyfill.stands_in_for,
                polyfill.difference or "",
            )
        for key, reason in sr.REGISTER.not_declared.items():
            yield str(key), (reason,)

    count = 0
    for owner, texts in sentences():
        for text in texts:
            count += 1
            assert text.isascii(), (owner, text)
    assert count > 150, count
