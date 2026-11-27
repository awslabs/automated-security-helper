"""The facts about the host that support rows match on, read in one place.

One reader answers each host question ASH has: the operating system and its release,
the architecture, binary translation (Rosetta, x64 emulation on arm64), how the x86-64
feature set compares with the two sets polars builds its runtimes for, which runtime
polars will load, libc, WSL, whether the interpreter is in ASH's range and which build
it is, how ASH was installed, and whether the express path is available.

How the reads work:

* No network and no child process. A read is a file (the processor flags, the kernel
  release, os-release, and the head of the interpreter's own executable, which names
  its program loader when the C library does not say glibc), a ctypes call (the macOS
  translation flag and feature strings, the Windows processor-feature and machine-type
  calls), a value the interpreter already holds, or an ``importlib.metadata`` lookup.
  No loader is ever run to ask it a version.
* Each fact is one token of a closed set (``TOKENS``). A reader that fails, or that
  cannot tell, gives ``unknown``, and ``unknown`` matches no row that marks a host as
  unsupported, so detection never stops a scan and never guesses.
  ``HostReading.failed`` names the facts whose reader raised and the exception type,
  never its text.
* Every read goes through ``Sources``, a record of callables. The live ones are the
  defaults and a test plants all of them, so no test reads the machine it runs on.
* What cannot change within a process (processor flags, translation, libc, the
  installed distributions) is read once per reader, and a failed read is remembered,
  not retried. What a request can change (``POLARS_FORCE_PKG``, ``POLARS_PREFER_PKG``,
  ``ASH_IN_CONTAINER``, the uv and pipx directories, the home directory) is read on
  every call.
* ``fact_tokens`` is the one mapping from a reading onto the fields a support row
  matches on.
* ``express_supported`` is passed in by the caller: this module sits in ``utils``,
  which may not import ``express``.

The processor reads import nothing. The runtime polars will load is decided from the
installed ``polars-runtime-*`` distributions, in polars' own order of preference, and
each runtime's required flags are read as text from its generated
``build_feature_flags.py`` through the distribution's file list. ``cpu_level`` is
answered only when that file equals the set declared here; against any other file the
level is ``unknown``, because the flags a runtime needs are no longer known. The reader
does not look at ``POLARS_SKIP_CPU_CHECK``: that variable silences polars' own check,
and the host's processor is the same either way.

Versions are compared here when they are plain, only digits and dots as in ``1.44.2``,
so the version checks of a usual reading import nothing from ``packaging``. A version of
any other shape (a pre-release, an epoch, a ``v`` prefix) and a ``Requires-Python`` that
is not made of plain bounds go to ``packaging``, whose answer and whose errors are the
reader's own.

A distribution's version and ASH's ``Requires-Python`` are the header lines of its
``METADATA`` text, read as text: that takes the metadata parser's milliseconds out of
the first reading. A text that is not made of plain headers goes to the parser, and the
runtimes polars would try only after the one that loads are never looked up.

This module is the only reader of ``/proc/cpuinfo``, the macOS translation sysctl and
the two Windows calls named in ``tests/unit/utils/test_host_facts_single_reader.py``,
which holds the rest of the package to that. It imports nothing else from ASH and
nothing from polars, and everything beyond a few cheap standard-library modules is
imported inside the function that needs it.
"""

from __future__ import annotations

import dataclasses
import os
import posixpath
import sys
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Iterable,
    Iterator,
    Literal,
    Mapping,
    NamedTuple,
    NoReturn,
    Optional,
)

if TYPE_CHECKING:
    from importlib.metadata import Distribution

__all__ = [
    "COMPAT_RUNTIME_FLAGS",
    "DEFAULT_PREFERENCE",
    "DEFAULT_RUNTIME_FLAGS",
    "FACT_FIELDS",
    "FLAG_SPELLINGS",
    "POLARS_BELOW_VERSION",
    "POLARS_MIN_VERSION",
    "RUNTIME_CHOICES",
    "RUNTIME_FLAGS",
    "TOKENS",
    "UNKNOWN",
    "FlagSpelling",
    "HostFactsReader",
    "HostReading",
    "Sources",
    "choose_runtime",
    "cpu_level_from_reports",
    "fact_tokens",
    "parse_flags_file",
    "read_host_facts",
    "read_libc",
    "read_os_release",
    "read_runtime_flags",
    "runtime_flags_match",
    "split_build_flags",
    "windows_constants_for_build",
]

UNKNOWN = "unknown"
NOT_APPLICABLE = "n/a"

_OS_TOKENS = ("linux", "darwin", "windows", "other", UNKNOWN)

#: The closed vocabulary of each fact a host reader decides. ``os_release`` is free
#: text that no row matches on, so it has no entry.
TOKENS: Mapping[str, tuple[str, ...]] = {
    "os": _OS_TOKENS,
    "host_os": _OS_TOKENS,
    "arch": ("amd64", "arm64", "other", UNKNOWN),
    "translation": ("native", "rosetta", "x64-on-arm64", UNKNOWN),
    "cpu_level": ("full", "compat-only", "below-compat", NOT_APPLICABLE, UNKNOWN),
    "polars_runtime": ("runtime-32", "runtime-64", "compat", "absent", UNKNOWN),
    "libc": ("glibc", "musl", NOT_APPLICABLE, UNKNOWN),
    "python_in_range": ("yes", "no", UNKNOWN),
    "python_build": ("standard", "free-threaded", "other-implementation", UNKNOWN),
    "install_channel": (
        "uv-tool",
        "uvx",
        "pipx",
        "pip",
        "brew",
        "nix",
        "image",
        "source",
        UNKNOWN,
    ),
    "wsl": ("wsl2", "wsl1", "no", NOT_APPLICABLE, UNKNOWN),
    "express_available": ("yes", "no", UNKNOWN),
}

#: The fields of a reading that a support row can match on, in the order a support
#: row lists them. ``os_release`` is recorded in the reading beside them and no row
#: matches on it, so it is not one of them.
FACT_FIELDS: tuple[str, ...] = (
    "os",
    "host_os",
    "arch",
    "translation",
    "cpu_level",
    "polars_runtime",
    "libc",
    "python_in_range",
    "python_build",
    "install_channel",
    "wsl",
    "express_available",
)

#: Every fact a reading holds, in the order it holds them: the fields a row matches on,
#: and ``os_release`` after the two operating-system facts. ``HostReading.failed`` names
#: the facts whose reader failed in this order.
_READING_FACTS: tuple[str, ...] = (*FACT_FIELDS[:2], "os_release", *FACT_FIELDS[2:])

# --------------------------------------------------------------------------------------
# What polars needs
# --------------------------------------------------------------------------------------

#: The x86-64 features the default runtimes (32 and 64) are built for, in the order
#: polars' release workflow lists them. The compatibility runtime keeps the first six.
DEFAULT_RUNTIME_FLAGS: tuple[str, ...] = (
    "sse3",
    "ssse3",
    "sse4.1",
    "sse4.2",
    "popcnt",
    "cmpxchg16b",
    "avx",
    "avx2",
    "fma",
    "bmi1",
    "bmi2",
    "lzcnt",
    "pclmulqdq",
    "movbe",
)
COMPAT_RUNTIME_FLAGS: tuple[str, ...] = DEFAULT_RUNTIME_FLAGS[:6]

#: The flags each runtime token is built for.
RUNTIME_FLAGS: Mapping[str, tuple[str, ...]] = {
    "runtime-32": DEFAULT_RUNTIME_FLAGS,
    "runtime-64": DEFAULT_RUNTIME_FLAGS,
    "compat": COMPAT_RUNTIME_FLAGS,
}

#: polars' selector for each runtime, the token the reader reports and the name of the
#: distribution that carries it.
RUNTIME_CHOICES: Mapping[str, tuple[str, str]] = {
    "compat": ("compat", "polars-runtime-compat"),
    "64": ("runtime-64", "polars-runtime-64"),
    "32": ("runtime-32", "polars-runtime-32"),
}
#: The order polars tries its runtimes in when neither variable says otherwise.
DEFAULT_PREFERENCE: tuple[str, ...] = ("compat", "64", "32")

#: The range of polars versions ASH declares (``polars>=1.33,<2.0``). Outside it the
#: reader cannot know how polars chooses a runtime.
POLARS_MIN_VERSION: tuple[int, ...] = (1, 33)
POLARS_BELOW_VERSION: tuple[int, ...] = (2, 0)

_MACOS_FEATURES = "machdep.cpu.features"
_MACOS_LEAF7 = "machdep.cpu.leaf7_features"
_MACOS_EXTENDED = "machdep.cpu.extfeatures"
_MACOS_KEYS = (_MACOS_FEATURES, _MACOS_LEAF7, _MACOS_EXTENDED)


class FlagSpelling(NamedTuple):
    """How each platform names one of polars' CPU flags.

    ``linux`` holds the spellings of the first ``flags`` line of ``/proc/cpuinfo``:
    the kernel's own, then polars' when they differ (the kernel prints polars' sse3,
    sse4.1, sse4.2, cmpxchg16b and lzcnt as pni, sse4_1, sse4_2, cx16 and abm).
    ``windows`` is the ``IsProcessorFeaturePresent`` constant, or None where Windows
    has none. ``macos`` is the ``machdep.cpu`` string that lists the feature, and the
    token it appears as in that string.
    """

    linux: tuple[str, ...]
    windows: Optional[int]
    macos: tuple[str, str]


FLAG_SPELLINGS: Mapping[str, FlagSpelling] = {
    "sse3": FlagSpelling(("pni", "sse3"), 13, (_MACOS_FEATURES, "SSE3")),
    "ssse3": FlagSpelling(("ssse3",), 36, (_MACOS_FEATURES, "SSSE3")),
    "sse4.1": FlagSpelling(("sse4_1", "sse4.1"), 37, (_MACOS_FEATURES, "SSE4.1")),
    "sse4.2": FlagSpelling(("sse4_2", "sse4.2"), 38, (_MACOS_FEATURES, "SSE4.2")),
    "popcnt": FlagSpelling(("popcnt",), None, (_MACOS_FEATURES, "POPCNT")),
    "cmpxchg16b": FlagSpelling(("cx16", "cmpxchg16b"), 14, (_MACOS_FEATURES, "CX16")),
    "avx": FlagSpelling(("avx",), 39, (_MACOS_FEATURES, "AVX1.0")),
    "avx2": FlagSpelling(("avx2",), 40, (_MACOS_LEAF7, "AVX2")),
    "fma": FlagSpelling(("fma",), None, (_MACOS_FEATURES, "FMA")),
    "bmi1": FlagSpelling(("bmi1",), None, (_MACOS_LEAF7, "BMI1")),
    "bmi2": FlagSpelling(("bmi2",), 60, (_MACOS_LEAF7, "BMI2")),
    "lzcnt": FlagSpelling(("abm", "lzcnt"), None, (_MACOS_EXTENDED, "LZCNT")),
    "pclmulqdq": FlagSpelling(("pclmulqdq",), None, (_MACOS_FEATURES, "PCLMULQDQ")),
    "movbe": FlagSpelling(("movbe",), None, (_MACOS_FEATURES, "MOVBE")),
}

#: The first Windows build whose ``IsProcessorFeaturePresent`` answers each flag's
#: constant. Before Windows 10 2004 (19041) a zero for the newer constants proves
#: nothing, and BMI2 has a constant only from Windows 11 24H2 (26100).
_WINDOWS_FIRST_BUILD: Mapping[str, int] = {
    "sse3": 0,
    "cmpxchg16b": 0,
    "ssse3": 19041,
    "sse4.1": 19041,
    "sse4.2": 19041,
    "avx": 19041,
    "avx2": 19041,
    "bmi2": 26100,
}


def _flags_by_windows_constant() -> dict[int, str]:
    table: dict[int, str] = {}
    for flag, spelling in FLAG_SPELLINGS.items():
        if spelling.windows is not None:
            table[spelling.windows] = flag
    return table


_FLAG_OF_CONSTANT: Mapping[int, str] = _flags_by_windows_constant()

_IMAGE_MACHINE_I386 = 0x014C
_IMAGE_MACHINE_AMD64 = 0x8664
_IMAGE_MACHINE_ARM64 = 0xAA64

#: How much of a host file a reader looks at.
_CPUINFO_LIMIT = 65536
_KERNEL_RELEASE_LIMIT = 4096
_FLAGS_FILE_LIMIT = 4096
#: The head of the interpreter's executable that is read to find its program loader,
#: and how many program headers are looked at in it. The loader is named by the first
#: segments of an executable, well inside the head.
_ELF_HEAD_LIMIT = 4096
_ELF_HEADERS_LIMIT = 64
_NAME_LIMIT = 32
#: A version text longer than this is left to ``packaging`` rather than read here.
_PLAIN_LIMIT = 64

_IMAGE_VARIABLE = "ASH_IN_CONTAINER"
_FORCE_VARIABLE = "POLARS_FORCE_PKG"
_PREFER_VARIABLE = "POLARS_PREFER_PKG"
_ASH_DISTRIBUTION = "automated-security-helper"
_TRUE_VALUES = ("YES", "1", "TRUE")


# --------------------------------------------------------------------------------------
# The live sources
# --------------------------------------------------------------------------------------


def _live_sys_platform() -> str:
    return sys.platform


def _live_machine() -> str:
    return os.uname().machine


def _live_sysconfig_platform() -> str:
    import sysconfig

    return sysconfig.get_platform()


def _live_pointer_bits() -> int:
    return 64 if sys.maxsize > 2**32 else 32


def _live_read_head(path: str, limit: int) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(limit)


def _live_read_text(path: str, limit: int) -> str:
    return _live_read_head(path, limit).decode("utf-8", errors="replace")


def _live_freedesktop_os_release() -> Mapping[str, str]:
    import platform

    return platform.freedesktop_os_release()


def _live_mac_version() -> str:
    import platform

    return platform.mac_ver()[0]


def _live_windows_version() -> tuple[int, int, int]:
    version = sys.getwindowsversion()  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    return (version.major, version.minor, version.build)


def _raise_errno(code: int) -> NoReturn:
    raise OSError(code, os.strerror(code))


def _live_sysctl_int(name: str) -> int:
    import ctypes

    libc = ctypes.CDLL("libc.dylib", use_errno=True)
    value = ctypes.c_int(0)
    size = ctypes.c_size_t(ctypes.sizeof(value))
    key = name.encode("ascii")
    if libc.sysctlbyname(key, ctypes.byref(value), ctypes.byref(size), None, 0) != 0:
        _raise_errno(ctypes.get_errno())
    return int(value.value)


def _live_sysctl_str(name: str) -> str:
    import ctypes

    libc = ctypes.CDLL("libc.dylib", use_errno=True)
    key = name.encode("ascii")
    size = ctypes.c_size_t(0)
    if libc.sysctlbyname(key, None, ctypes.byref(size), None, 0) != 0:
        _raise_errno(ctypes.get_errno())
    buffer = ctypes.create_string_buffer(size.value or 1)
    if libc.sysctlbyname(key, buffer, ctypes.byref(size), None, 0) != 0:
        _raise_errno(ctypes.get_errno())
    return buffer.value.decode("utf-8", errors="replace")


def _live_wow64_machines() -> tuple[int, int]:
    """``(process machine, native machine)`` from the machine-type call.

    The process machine is 0 for every process that is not WOW64: one that runs
    natively, and an x64 one under emulation on Windows on Arm, which has no WOW64
    layer. The function does not exist before Windows 10 1511: its absence is an
    ``AttributeError``, which the reader reports as ``unknown``.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    function = kernel32.IsWow64Process2
    function.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.USHORT),
        ctypes.POINTER(wintypes.USHORT),
    ]
    function.restype = wintypes.BOOL
    process_machine = wintypes.USHORT(0)
    native_machine = wintypes.USHORT(0)
    answered = function(
        kernel32.GetCurrentProcess(),
        ctypes.byref(process_machine),
        ctypes.byref(native_machine),
    )
    if not answered:
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    return (process_machine.value, native_machine.value)


def _live_windows_feature_present(constant: int) -> bool:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32")  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]
    kernel32.IsProcessorFeaturePresent.argtypes = [ctypes.c_uint32]
    kernel32.IsProcessorFeaturePresent.restype = ctypes.c_int
    return bool(kernel32.IsProcessorFeaturePresent(constant))


def _live_libc_version() -> str:
    version = os.confstr("CS_GNU_LIBC_VERSION")
    if version is None:
        raise ValueError("no C library version")
    return version


def _live_executable() -> str:
    """The path of the running interpreter's executable, empty when it has none."""
    return sys.executable or ""


def _live_distribution(name: str) -> Optional[Distribution]:
    import importlib.metadata

    try:
        return importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _live_getenv(name: str) -> Optional[str]:
    return os.environ.get(name)


def _live_sys_prefix() -> str:
    return sys.prefix


def _live_realpath(path: str) -> str:
    return os.path.realpath(path)


def _live_home() -> Optional[str]:
    """The home directory when it names its location by itself, else None."""
    home = os.path.expanduser("~")
    if home == "~" or not os.path.isabs(home) or os.path.dirname(home) == home:
        return None
    return home


def _live_python_version() -> tuple[int, int, int, str, int]:
    version = sys.version_info
    return (
        version.major,
        version.minor,
        version.micro,
        version.releaselevel,
        version.serial,
    )


def _live_implementation_name() -> str:
    return sys.implementation.name


def _live_gil_disabled() -> bool:
    import sysconfig

    return bool(sysconfig.get_config_var("Py_GIL_DISABLED"))


def _live_polars_plr_injected() -> bool:
    """Whether something has put its own polars core in place (polars' ``_plr`` check)."""
    import builtins

    return hasattr(builtins, "__POLARS_PLR")


@dataclasses.dataclass(frozen=True)
class Sources:
    """Every host read the facts depend on, as a callable. The defaults read this host.

    A test plants every field. A source may raise: the reader turns the failure into
    ``unknown`` for the facts that depend on it.
    """

    # The interpreter and the machine.
    sys_platform: Callable[[], str] = _live_sys_platform
    machine: Callable[[], str] = _live_machine
    sysconfig_platform: Callable[[], str] = _live_sysconfig_platform
    pointer_bits: Callable[[], int] = _live_pointer_bits
    # Files and operating-system strings.
    read_text: Callable[[str, int], str] = _live_read_text
    freedesktop_os_release: Callable[[], Mapping[str, str]] = (
        _live_freedesktop_os_release
    )
    mac_version: Callable[[], str] = _live_mac_version
    windows_version: Callable[[], tuple[int, int, int]] = _live_windows_version
    # macOS and Windows system calls.
    sysctl_int: Callable[[str], int] = _live_sysctl_int
    sysctl_str: Callable[[str], str] = _live_sysctl_str
    wow64_machines: Callable[[], tuple[int, int]] = _live_wow64_machines
    windows_feature_present: Callable[[int], bool] = _live_windows_feature_present
    # libc: the C library's own answer, and the interpreter's executable, whose head
    # names its program loader.
    libc_version: Callable[[], str] = _live_libc_version
    executable: Callable[[], str] = _live_executable
    read_head: Callable[[str, int], bytes] = _live_read_head
    # Installed software and where it lives.
    distribution: Callable[[str], Optional[Distribution]] = _live_distribution
    getenv: Callable[[str], Optional[str]] = _live_getenv
    sys_prefix: Callable[[], str] = _live_sys_prefix
    realpath: Callable[[str], str] = _live_realpath
    home: Callable[[], Optional[str]] = _live_home
    # The interpreter's build.
    python_version: Callable[[], tuple[int, int, int, str, int]] = _live_python_version
    implementation_name: Callable[[], str] = _live_implementation_name
    gil_disabled: Callable[[], bool] = _live_gil_disabled
    polars_plr_injected: Callable[[], bool] = _live_polars_plr_injected


# --------------------------------------------------------------------------------------
# The reading
# --------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class HostReading:
    """One reading of the host: the thirteen facts, then what a notice can name.

    ``cpu_missing_flags`` lists the flags of polars' default set that the host lacks, in
    polars' order. ``python_version`` and ``requires_python`` are the interpreter's
    version and ASH's own ``Requires-Python`` as recorded in its installed metadata,
    ``unknown`` when not known. ``failed`` holds ``(fact, exception type)`` for each
    fact whose reader raised; it never holds the exception's text.
    """

    os: str
    host_os: str
    os_release: str
    arch: str
    translation: str
    cpu_level: str
    polars_runtime: str
    libc: str
    python_in_range: str
    python_build: str
    install_channel: str
    wsl: str
    express_available: str
    cpu_missing_flags: tuple[str, ...] = ()
    python_version: str = UNKNOWN
    requires_python: str = UNKNOWN
    failed: tuple[tuple[str, str], ...] = ()


def fact_tokens(reading: HostReading) -> dict[str, str]:
    """The reading as the fields a support row matches on, in their order.

    The one place a reading is mapped onto those fields: the details beside the facts
    (``failed``, ``cpu_missing_flags``, ``python_version``) are not part of it, and
    neither is ``os_release``, which a reading records and no row matches on.
    """
    return {name: getattr(reading, name) for name in FACT_FIELDS}


# --------------------------------------------------------------------------------------
# The processor level, from what a host can report
# --------------------------------------------------------------------------------------


def cpu_level_from_reports(
    reports: Mapping[str, Optional[bool]],
) -> tuple[str, tuple[str, ...]]:
    """``(level, missing flags)`` from what a host reported for polars' default flags.

    A flag maps to True (present), False (absent), or None (the host could not be
    asked). A flag missing from the mapping is one the platform cannot report at all.

    * ``below-compat`` when a flag of the compatibility set is absent;
    * ``compat-only`` when the compatibility set is present and a default-only flag is
      absent, whatever else could not be asked;
    * ``full`` when every flag the platform reports is present and AVX2, the flag that
      separates the two sets, was among them;
    * ``unknown`` when too little was reported to tell, with no missing flags named.
    """
    missing = tuple(
        flag for flag in DEFAULT_RUNTIME_FLAGS if reports.get(flag) is False
    )
    compat = frozenset(COMPAT_RUNTIME_FLAGS)
    if any(flag in compat for flag in missing):
        return ("below-compat", missing)
    if any(flag in reports and reports[flag] is None for flag in COMPAT_RUNTIME_FLAGS):
        return (UNKNOWN, ())
    if missing:
        return ("compat-only", missing)
    if any(reports.get(flag, True) is None for flag in DEFAULT_RUNTIME_FLAGS):
        return (UNKNOWN, ())
    if reports.get("avx2") is True:
        return ("full", ())
    return (UNKNOWN, ())


def windows_constants_for_build(build: int) -> tuple[int, ...]:
    """The ``IsProcessorFeaturePresent`` constants this Windows build can answer."""
    constants = []
    for flag, spelling in FLAG_SPELLINGS.items():
        constant = spelling.windows
        if constant is not None and build >= _WINDOWS_FIRST_BUILD[flag]:
            constants.append(constant)
    return tuple(sorted(constants))


def _x86_flags(text: str, limit: int) -> Optional[frozenset[str]]:
    """The flags of the first ``flags`` line of a cpuinfo text, or None when unusable.

    The key is matched by name. A line without long mode and SSE2 is not an x86-64
    flags line, and a line the read may have cut short is not trusted.
    """
    lines = text.split("\n")
    for index, line in enumerate(lines):
        key, colon, value = line.partition(":")
        if not colon or key.strip() != "flags":
            continue
        if len(text) >= limit and index == len(lines) - 1:
            return None
        flags = frozenset(value.split())
        return flags if {"lm", "sse2"} <= flags else None
    return None


# --------------------------------------------------------------------------------------
# What polars loads, and what each runtime needs
# --------------------------------------------------------------------------------------


def split_build_flags(value: str) -> tuple[str, ...]:
    """The CPU flags a ``BUILD_FEATURE_FLAGS`` string requires, split as polars does.

    Entries that start with ``-`` are dropped, leading ``+`` signs are stripped, and
    empty entries and ``ctr-static``, which is not a CPU flag, are ignored.
    """
    flags = []
    for entry in value.split(","):
        if entry.startswith("-"):
            continue
        flag = entry.lstrip("+")
        if flag and flag != "ctr-static":
            flags.append(flag)
    return tuple(flags)


def _assigned_string(rest: str) -> Optional[str]:
    """The string literal in ``<name><rest>`` when ``rest`` is a plain assignment."""
    head, equals, tail = rest.partition("=")
    annotation = head.strip()
    if not equals or (annotation and not annotation.startswith(":")):
        return None
    value = tail.strip()
    if not value or value[0] not in "\"'":
        return None
    end = value.find(value[0], 1)
    if end < 0:
        return None
    after = value[end + 1 :].strip()
    body = value[1:end]
    if (after and not after.startswith("#")) or "\\" in body:
        return None
    return body


def parse_flags_file(text: str) -> Optional[tuple[str, ...]]:
    """The flags a generated ``build_feature_flags.py`` declares, read as text.

    The file is never imported or run. The reading is the last line that starts at
    column 0 with ``BUILD_FEATURE_FLAGS``, optionally annotated, and assigns one plain
    string literal; any other shape of that line, or no such line, gives None.
    """
    name = "BUILD_FEATURE_FLAGS"
    found = False
    value: Optional[str] = None
    for line in text.splitlines():
        if not line.startswith(name):
            continue
        rest = line[len(name) :]
        if not rest or rest[0] not in " \t:=":
            continue
        found = True
        value = _assigned_string(rest)
    if not found or value is None:
        return None
    return split_build_flags(value)


def read_runtime_flags(distribution: Any) -> Optional[tuple[str, ...]]:
    """The flags a runtime distribution requires, or None when they cannot be read.

    The generated file is found through the distribution's file list, in the runtime's
    own package directory, and read as bounded text. A file that is not listed, is gone,
    is larger than a generated one, or does not parse reads as None.
    """
    for entry in distribution.files or ():
        parts = entry.parts
        if not (
            len(parts) == 2
            and parts[0].startswith("_polars_runtime_")
            and parts[1] == "build_feature_flags.py"
        ):
            continue
        try:
            with open(distribution.locate_file(entry), "rb") as handle:
                raw = handle.read(_FLAGS_FILE_LIMIT + 1)
        except OSError:
            return None
        if len(raw) > _FLAGS_FILE_LIMIT:
            return None
        return parse_flags_file(raw.decode("utf-8", errors="replace"))
    return None


def runtime_flags_match(token: str, flags: Optional[Iterable[str]]) -> bool:
    """Whether ``flags`` are, as a set, what the runtime ``token`` is declared to need."""
    declared = RUNTIME_FLAGS.get(token)
    if flags is None or declared is None:
        return False
    return set(flags) == set(declared)


def _drop_zeros(release: Iterable[int]) -> tuple[int, ...]:
    """The numbers of a release without the zeros at its end: ``1.33.0`` is ``1.33``."""
    parts = list(release)
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _plain_release(text: str) -> Optional[tuple[int, ...]]:
    """The release of a text made only of ASCII digit groups and dots, else None.

    PEP 440 orders two plain versions by these numbers, trailing zeros dropped. Any
    other text (a pre-release, an epoch, a ``v`` prefix, padding, a digit that is not
    ASCII, or more than ``_PLAIN_LIMIT`` characters) is left to ``packaging``, so what
    it reads and what it raises stay what they were.
    """
    if not text or len(text) > _PLAIN_LIMIT:
        return None
    parts = text.split(".")
    if not all(part.isascii() and part.isdigit() for part in parts):
        return None
    return _drop_zeros(int(part) for part in parts)


def _polars_in_range(version: str) -> bool:
    release = _plain_release(version)
    if release is not None:
        low = _drop_zeros(POLARS_MIN_VERSION)
        high = _drop_zeros(POLARS_BELOW_VERSION)
        return low <= release < high
    from packaging.specifiers import SpecifierSet
    from packaging.version import InvalidVersion, Version

    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    lower = ".".join(str(part) for part in POLARS_MIN_VERSION)
    upper = ".".join(str(part) for part in POLARS_BELOW_VERSION)
    return SpecifierSet(f">={lower},<{upper}").contains(parsed, prereleases=True)


def _same_version(first: str, second: str) -> bool:
    if first == second:
        return True
    # Both plain, or packaging decides: ``v1.44.2`` is ``1.44.2``, and one plain side
    # says nothing about the other.
    plain_first = _plain_release(first)
    plain_second = _plain_release(second)
    if plain_first is not None and plain_second is not None:
        return plain_first == plain_second
    from packaging.version import InvalidVersion, Version

    try:
        return Version(first) == Version(second)
    except InvalidVersion:
        return False


def _runtime_order(
    polars_version: Optional[str],
    *,
    force: Optional[str],
    prefer: Optional[str],
    injected: bool,
) -> Optional[tuple[str, ...]]:
    """The selectors polars tries, in its order, or None when that cannot be known.

    polars tries the compatibility runtime, then the 64 one, then the 32 one;
    ``POLARS_PREFER_PKG`` puts one first, and ``POLARS_FORCE_PKG`` tries that one alone,
    whether or not it is set to anything. None is polars missing or out of range,
    something that has put its own core in place, or a variable that names no runtime.
    """
    if injected or polars_version is None or not _polars_in_range(polars_version):
        return None
    if force is not None:
        return (force,) if force in RUNTIME_CHOICES else None
    if prefer is None:
        return DEFAULT_PREFERENCE
    return (prefer, *DEFAULT_PREFERENCE) if prefer in RUNTIME_CHOICES else None


def choose_runtime(
    polars_version: Optional[str],
    runtimes: Mapping[str, str],
    *,
    force: Optional[str],
    prefer: Optional[str],
    injected: bool,
) -> tuple[str, Optional[str]]:
    """``(token, selector)`` for the runtime polars will load, as polars chooses it.

    ``runtimes`` maps each installed selector (``compat``, ``64``, ``32``) to the
    version of its distribution. polars tries them in the order of ``_runtime_order``,
    and a runtime of another version than polars is skipped. The token is ``absent``
    when none can load, and ``unknown`` when polars is missing or out of range, a
    variable names no runtime, or something has put its own core in place.
    """
    order = _runtime_order(
        polars_version, force=force, prefer=prefer, injected=injected
    )
    if order is None or polars_version is None:
        return (UNKNOWN, None)
    for selector in order:
        version = runtimes.get(selector)
        if version is not None and _same_version(version, polars_version):
            return (RUNTIME_CHOICES[selector][0], selector)
    return ("absent", None)


# --------------------------------------------------------------------------------------
# Small readers of text
# --------------------------------------------------------------------------------------


def _is_plain(token: str) -> bool:
    """A run of ASCII letters, digits, dots, underscores and hyphens."""
    return (
        bool(token)
        and token.isascii()
        and token[0].isalnum()
        and all(char.isalnum() or char in "._-" for char in token)
    )


def _first_token(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    parts = value.split()
    return parts[0] if parts else None


def _linux_release(mapping: Mapping[str, str]) -> str:
    """``<id> <version>`` from os-release, keeping only plain tokens: it is host data."""
    identity = _first_token(mapping.get("ID"))
    if identity is None:
        return UNKNOWN
    identity = identity.lower()
    if not _is_plain(identity):
        return UNKNOWN
    version = _first_token(mapping.get("VERSION_ID"))
    if version is None or not _is_plain(version):
        return identity[:_NAME_LIMIT]
    return f"{identity[:_NAME_LIMIT]} {version[:_NAME_LIMIT]}"


def _macos_release(version: str) -> str:
    token = _first_token(version)
    if token is None or not (
        token[0].isdigit() and all(char.isdigit() or char == "." for char in token)
    ):
        return UNKNOWN
    return f"macos {token[:_NAME_LIMIT]}"


def _windows_release(version: Iterable[int]) -> str:
    return "windows " + ".".join(str(int(part)) for part in version)


_RELEASE_SUFFIX = {"alpha": "a", "beta": "b", "candidate": "rc"}
_SPECIFIER_RANK = {
    ">=": 0,
    ">": 0,
    "~=": 0,
    "==": 1,
    "===": 1,
    "!=": 2,
    "<=": 3,
    "<": 3,
}


def _canonical_text(pairs: Iterable[tuple[str, str]]) -> str:
    """Specifiers as ``(operator, text)``, lower bounds first: ``>=3.11,<3.15``."""
    ordered = sorted(pairs, key=lambda pair: (_SPECIFIER_RANK.get(pair[0], 4), pair[1]))
    return ",".join(text for _operator, text in ordered)


def _canonical_specifiers(specifiers: Any) -> str:
    """The ``packaging`` specifier set with its lower bounds first."""
    return _canonical_text((spec.operator, str(spec)) for spec in specifiers)


_PLAIN_OPERATORS = ("<=", ">=", "==", "!=", "<", ">")


def _plain_holds(
    comparison: str, release: tuple[int, ...], bound: tuple[int, ...]
) -> bool:
    if comparison == ">=":
        return release >= bound
    if comparison == "<=":
        return release <= bound
    if comparison == "==":
        return release == bound
    if comparison == "!=":
        return release != bound
    if comparison == "<":
        return release < bound
    return release > bound


def _plain_requires(header: str, version_text: str) -> Optional[tuple[str, bool]]:
    """``(canonical text, inside)`` for plain bounds against a plain version, else None.

    A plain header is one or more comma-separated pieces, each ``<``, ``<=``, ``>``,
    ``>=``, ``==`` or ``!=`` directly followed by a plain release, and ``version_text``
    is a plain release too. None leaves the header to ``packaging``: that is what every
    other shape gets, and so do an empty set and two pieces that name one bound, which
    ``packaging`` folds into the first.
    """
    release = _plain_release(version_text)
    if release is None:
        return None
    pieces: list[tuple[str, str]] = []
    named: set[tuple[str, tuple[int, ...]]] = set()
    inside = True
    for raw in header.split(","):
        piece = raw.strip()
        if not piece:
            continue
        comparison = next((op for op in _PLAIN_OPERATORS if piece.startswith(op)), None)
        if comparison is None:
            return None
        bound = _plain_release(piece[len(comparison) :])
        if bound is None or (comparison, bound) in named:
            return None
        named.add((comparison, bound))
        pieces.append((comparison, piece))
        inside = inside and _plain_holds(comparison, release, bound)
    if not pieces:
        return None
    return (_canonical_text(pieces), inside)


def _is_editable(direct_url: Optional[str]) -> bool:
    """Whether a PEP 610 record says the install is editable."""
    if not direct_url:
        return False
    import json

    try:
        data = json.loads(direct_url)
    except ValueError:
        return False
    info = data.get("dir_info") if isinstance(data, dict) else None
    return isinstance(info, dict) and info.get("editable") is True


def _plain_header(text: Optional[str], name: str) -> tuple[bool, Optional[str]]:
    """``(plain, value)``: the first header ``name`` of a plain ``METADATA`` text.

    ``email`` parses a distribution's metadata, and the first parse costs milliseconds.
    A text that is only ``Name: value`` lines and indented continuation lines is read
    here instead, and gives what ``email`` gives: the text after the colon with its
    leading spaces and tabs dropped and nothing else, from the first header of that
    name in whatever case it is spelled. ``value`` is None when the block has no such
    header. ``plain`` is False for every other text, so the caller asks ``email`` and
    its answer stands: no text, a carriage return, a first line that continues
    nothing, a line that is neither a header nor a continuation (``email`` ends the
    headers there), a header name of anything but printable ASCII, and a wanted header
    whose value goes on over more lines.
    """
    if not text or "\r" in text:
        return (False, None)
    lines = text.split("\n\n", 1)[0].split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    wanted = name.lower()
    for index, line in enumerate(lines):
        if line.startswith((" ", "\t")):
            if index == 0:
                return (False, None)
            continue
        key, colon, value = line.partition(":")
        if not colon or not key or not all("!" <= char <= "~" for char in key):
            return (False, None)
        if key.lower() == wanted:
            following = lines[index + 1 : index + 2]
            if following and following[0].startswith((" ", "\t")):
                return (False, None)
            return (True, value.lstrip(" \t"))
    return (True, None) if lines else (False, None)


_PT_INTERP = 3
#: The file names of the program loaders glibc ships (``ld-linux-x86-64.so.2``,
#: ``ld64.so.2``, ``ld.so.1``).
_GLIBC_LOADERS = ("ld-linux", "ld64.so", "ld.so")


def _elf_interpreter(head: bytes) -> Optional[str]:
    """The program loader that the head of an ELF executable names, else None.

    The loader is the string of the ``PT_INTERP`` program header, such as
    ``/lib/ld-musl-x86_64.so.1`` on musl or ``/lib64/ld-linux-x86-64.so.2`` on glibc.
    ``head`` is the first bytes of the file, and nothing past it is read. None means a
    file that is not an ELF executable, a head that stops before the program header
    table or before the loader's name, or an executable with no loader (a static one).
    """
    if len(head) < 6 or head[:4] != b"\x7fELF" or head[4] not in (1, 2):
        return None
    if head[5] not in (1, 2):
        return None
    wide = head[4] == 2
    order: Literal["little", "big"] = "little" if head[5] == 1 else "big"

    def field(start: int, size: int) -> Optional[int]:
        if start + size > len(head):
            return None
        return int.from_bytes(head[start : start + size], order)

    # Where the program header table starts, how big an entry is, and how many there
    # are; then, in an entry, where the segment's file offset and length are.
    if wide:
        table, size, count = field(0x20, 8), field(0x36, 2), field(0x38, 2)
        smallest, offset_at, length_at, word = 56, 8, 32, 8
    else:
        table, size, count = field(0x1C, 4), field(0x2A, 2), field(0x2C, 2)
        smallest, offset_at, length_at, word = 32, 4, 16, 4
    if table is None or size is None or count is None or size < smallest:
        return None
    for index in range(min(count, _ELF_HEADERS_LIMIT)):
        entry = table + index * size
        kind = field(entry, 4)
        if kind is None:
            return None
        if kind != _PT_INTERP:
            continue
        offset = field(entry + offset_at, word)
        length = field(entry + length_at, word)
        if offset is None or length is None or offset + length > len(head):
            return None
        name, terminator, _rest = head[offset : offset + length].partition(b"\x00")
        return name.decode("utf-8", errors="replace") if terminator else None
    return None


# --------------------------------------------------------------------------------------
# Failures
# --------------------------------------------------------------------------------------


class _Failure(NamedTuple):
    """What is kept of a failed read: the exception's type, never its text."""

    kind: str
    os_error: bool
    errno: Optional[int]


class _SourceFailure(Exception):
    """A read that failed, raised again each time the failed result is asked for."""

    def __init__(self, failure: _Failure) -> None:
        super().__init__(failure.kind)
        self.failure = failure


def _failure_of(exc: BaseException) -> _Failure:
    if isinstance(exc, _SourceFailure):
        return exc.failure
    if isinstance(exc, OSError):
        return _Failure(type(exc).__name__, True, exc.errno)
    return _Failure(type(exc).__name__, False, None)


def _kind(exc: BaseException) -> str:
    return _failure_of(exc).kind


class _Runtime(NamedTuple):
    token: str
    distribution: Optional[Distribution]


# --------------------------------------------------------------------------------------
# The reader
# --------------------------------------------------------------------------------------


class HostFactsReader:
    """Reads the facts of one host through its ``Sources``.

    What cannot change within a process is read once and remembered, a failure
    included. The variables a request can change are read on every ``read``.
    """

    def __init__(self, sources: Optional[Sources] = None) -> None:
        self._sources = Sources() if sources is None else sources
        self._memo: dict[tuple[Any, ...], tuple[Any, Optional[_Failure]]] = {}

    def _remember(self, key: tuple[Any, ...], compute: Callable[[], Any]) -> Any:
        entry = self._memo.get(key)
        if entry is None:
            try:
                entry = (compute(), None)
            except Exception as exc:
                entry = (None, _failure_of(exc))
            self._memo[key] = entry
        value, failure = entry
        if failure is not None:
            raise _SourceFailure(failure)
        return value

    def _src(self, name: str, *args: Any) -> Any:
        function = getattr(self._sources, name)
        return self._remember((name, *args), lambda: function(*args))

    def _version(self, name: str, distribution: Distribution) -> str:
        """The installed version of a distribution, read once per reader."""
        version: str = self._remember(
            ("version", name), lambda: self._read_version(distribution)
        )
        return version

    @staticmethod
    def _read_version(distribution: Distribution) -> str:
        # The Version: line of the METADATA text, which is where ``distribution.version``
        # gets it by parsing the whole text. Any text that is not a plain header block
        # goes to that parse, and so do its errors.
        by_line, value = _plain_header(distribution.read_text("METADATA"), "Version")
        if by_line and value is not None:
            return value
        return distribution.version

    # ---- the platform ------------------------------------------------------------

    def _platform(self) -> str:
        raw = self._src("sys_platform")
        if raw.startswith("linux"):
            return "linux"
        return {"darwin": "darwin", "win32": "windows"}.get(raw, "other")

    def _arch(self) -> str:
        platform = self._platform()
        bits = self._src("pointer_bits")
        if platform == "windows":
            name = str(self._src("sysconfig_platform")).strip().lower()
            if not name:
                return UNKNOWN
            if "amd64" in name or "x86_64" in name:
                family = "amd64"
            elif "arm64" in name or "aarch64" in name:
                family = "arm64"
            else:
                family = "other"
        else:
            name = str(self._src("machine")).strip().lower()
            if not name:
                return UNKNOWN
            family = {
                "x86_64": "amd64",
                "amd64": "amd64",
                "aarch64": "arm64",
                "arm64": "arm64",
            }.get(name, "other")
        return family if bits == 64 else "other"

    def os_release(self) -> str:
        """The recorded release text (``ubuntu 24.04``); no row matches on it."""
        platform = self._platform()
        if platform == "linux":
            return _linux_release(self._src("freedesktop_os_release"))
        if platform == "darwin":
            return _macos_release(self._src("mac_version"))
        if platform == "windows":
            return _windows_release(self._src("windows_version"))
        return UNKNOWN

    def _translation(self) -> str:
        platform = self._platform()
        if platform == "linux":
            return "native"
        if platform == "darwin":
            import errno

            try:
                translated = self._src("sysctl_int", "sysctl.proc_translated")
            except _SourceFailure as failure:
                # The name is absent on Intel Macs and on older macOS: the process is native.
                if failure.failure.errno == errno.ENOENT:
                    return "native"
                raise
            return {1: "rosetta", 0: "native"}.get(translated, UNKNOWN)
        if platform == "windows":
            process_machine, native_machine = self._src("wow64_machines")
            if process_machine == 0:
                if native_machine != _IMAGE_MACHINE_ARM64:
                    return "native"
                # Windows on Arm runs an x64 process under emulation with no WOW64
                # layer, so IsWow64Process2 names no process machine for it either (it
                # reports the unknown machine for every process that is not WOW64).
                # Beside an arm64 native machine the call cannot tell an x64 Python
                # from an arm64 one, and the interpreter's own architecture can.
                return {"amd64": "x64-on-arm64", "arm64": "native"}.get(
                    self._arch(), UNKNOWN
                )
            if process_machine == _IMAGE_MACHINE_I386:
                # 32-bit x86 on 64-bit x86 Windows translates nothing. Emulated on arm64
                # it has no token.
                return "native" if native_machine == _IMAGE_MACHINE_AMD64 else UNKNOWN
            if (
                process_machine == _IMAGE_MACHINE_AMD64
                and native_machine == _IMAGE_MACHINE_ARM64
            ):
                return "x64-on-arm64"
        return UNKNOWN

    def _wsl(self) -> str:
        if self._platform() != "linux":
            return NOT_APPLICABLE
        text = self._src(
            "read_text", "/proc/sys/kernel/osrelease", _KERNEL_RELEASE_LIMIT
        )
        release = text.strip().lower()
        if not release:
            return UNKNOWN
        if "microsoft" not in release:
            return "no"
        return "wsl2" if "wsl2" in release else "wsl1"

    def libc(self) -> str:
        """``glibc`` or ``musl`` on Linux, ``n/a`` elsewhere."""
        if self._platform() != "linux":
            return NOT_APPLICABLE
        try:
            version = self._src("libc_version")
            if str(version).split()[:1] == ["glibc"]:
                return "glibc"
        except Exception:
            pass
        # The C library says nothing on musl. The program loader that the interpreter's
        # own executable names does, and it is read from the file: nothing is run (the
        # platform tags would run the loader to find a musl version).
        path = self._src("executable")
        if not path:
            return UNKNOWN
        loader = _elf_interpreter(self._src("read_head", path, _ELF_HEAD_LIMIT))
        if loader is None:
            return UNKNOWN
        if "musl" in loader:
            return "musl"
        if posixpath.basename(loader).startswith(_GLIBC_LOADERS):
            return "glibc"
        return UNKNOWN

    # ---- the processor and polars ------------------------------------------------

    def _runtime(self) -> _Runtime:
        injected = bool(self._sources.polars_plr_injected())
        force = self._sources.getenv(_FORCE_VARIABLE)
        prefer = None if force is not None else self._sources.getenv(_PREFER_VARIABLE)
        polars = self._src("distribution", "polars")
        polars_version = (
            None if polars is None or injected else self._version("polars", polars)
        )
        installed: dict[str, Distribution] = {}
        versions: dict[str, str] = {}
        order = _runtime_order(
            polars_version, force=force, prefer=prefer, injected=injected
        )
        # Only the runtimes polars tries before the one it loads are looked up: the
        # first whose version is polars' is that one, and nothing after it matters.
        if order is not None and polars_version is not None:
            for selector in order:
                distribution_name = RUNTIME_CHOICES[selector][1]
                distribution = self._src("distribution", distribution_name)
                if distribution is None:
                    continue
                installed[selector] = distribution
                versions[selector] = self._version(distribution_name, distribution)
                if _same_version(versions[selector], polars_version):
                    break
        token, chosen = choose_runtime(
            polars_version,
            versions,
            force=force,
            prefer=prefer,
            injected=injected,
        )
        return _Runtime(token, installed.get(chosen) if chosen else None)

    def _cpu_level(self, runtime: Optional[_Runtime]) -> tuple[str, tuple[str, ...]]:
        platform = self._platform()
        arch = self._arch()
        if arch in ("arm64", "other"):
            return (NOT_APPLICABLE, ())
        if arch != "amd64" or platform not in ("linux", "darwin", "windows"):
            return (UNKNOWN, ())
        # The level is judged against a runtime whose flags file is the declared set.
        if (
            runtime is None
            or runtime.distribution is None
            or runtime.token not in RUNTIME_FLAGS
        ):
            return (UNKNOWN, ())
        distribution = runtime.distribution
        flags = self._remember(
            ("runtime_flags", runtime.token), lambda: read_runtime_flags(distribution)
        )
        if not runtime_flags_match(runtime.token, flags):
            return (UNKNOWN, ())
        if platform == "linux":
            reports = self._linux_reports()
        elif platform == "darwin":
            reports = self._macos_reports()
        else:
            reports = self._windows_reports()
        return cpu_level_from_reports(reports)

    def _linux_reports(self) -> dict[str, Optional[bool]]:
        text = self._src("read_text", "/proc/cpuinfo", _CPUINFO_LIMIT)
        flags = _x86_flags(text, _CPUINFO_LIMIT)
        if flags is None:
            return {}
        return {
            flag: any(name in flags for name in FLAG_SPELLINGS[flag].linux)
            for flag in DEFAULT_RUNTIME_FLAGS
        }

    def _macos_reports(self) -> dict[str, Optional[bool]]:
        strings: dict[str, Optional[frozenset[str]]] = {}
        unreadable: list[_Failure] = []
        for key in _MACOS_KEYS:
            try:
                text = self._src("sysctl_str", key)
            except _SourceFailure as failure:
                if not failure.failure.os_error:
                    raise
                unreadable.append(failure.failure)
                strings[key] = None
                continue
            tokens = frozenset(token.upper() for token in str(text).split())
            # An empty leaf-7 string is a part with none of those features; an empty
            # features string is a read that told nothing.
            strings[key] = tokens if tokens or key == _MACOS_LEAF7 else None
        if len(unreadable) == len(_MACOS_KEYS):
            raise _SourceFailure(unreadable[0])
        reports: dict[str, Optional[bool]] = {}
        for flag in DEFAULT_RUNTIME_FLAGS:
            key, token = FLAG_SPELLINGS[flag].macos
            known = strings[key]
            reports[flag] = None if known is None else token.upper() in known
        return reports

    def _windows_reports(self) -> dict[str, Optional[bool]]:
        build = int(self._src("windows_version")[2])
        reports: dict[str, Optional[bool]] = {}
        for constant in windows_constants_for_build(build):
            present = self._src("windows_feature_present", constant)
            reports[_FLAG_OF_CONSTANT[constant]] = bool(present)
        return reports

    # ---- the interpreter ---------------------------------------------------------

    def _python_version_text(self) -> str:
        major, minor, micro, level, serial = self._src("python_version")
        if level == "final":
            return f"{major}.{minor}.{micro}"
        return f"{major}.{minor}.{micro}{_RELEASE_SUFFIX[level]}{serial}"

    def _requires_python(self, version_text: str) -> tuple[str, str]:
        """``(requires text, in range)`` from ASH's own installed metadata.

        Read once per reader, a failure included: ASH's metadata is parsed once.
        """
        result: tuple[str, str] = self._remember(
            ("requires_python", version_text),
            lambda: self._read_requires_python(version_text),
        )
        return result

    def _read_requires_python(self, version_text: str) -> tuple[str, str]:
        ash = self._src("distribution", _ASH_DISTRIBUTION)
        if ash is None:
            return (UNKNOWN, UNKNOWN)
        by_line, header = _plain_header(ash.read_text("METADATA"), "Requires-Python")
        if not by_line:
            # Any text that is not a plain header block is parsed, as it always was.
            metadata = ash.metadata
            # A missing key is a warned implicit None on some Pythons and a KeyError on
            # others, so ask whether it is there first.
            header = (
                metadata["Requires-Python"] if "Requires-Python" in metadata else None
            )
        if not header or not header.strip():
            return (UNKNOWN, UNKNOWN)
        plain = _plain_requires(header, version_text)
        if plain is not None:
            text, inside = plain
            return (text, "yes" if inside else "no")
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        specifiers = SpecifierSet(header)
        contained = specifiers.contains(Version(version_text), prereleases=True)
        return (_canonical_specifiers(specifiers), "yes" if contained else "no")

    def _python_build(self) -> str:
        if self._src("implementation_name") != "cpython":
            return "other-implementation"
        return "free-threaded" if self._src("gil_disabled") else "standard"

    # ---- how ASH was installed ---------------------------------------------------

    def _install_channel(self) -> str:
        platform = self._platform()
        flag = self._sources.getenv(_IMAGE_VARIABLE)
        if flag is not None and flag.upper() in _TRUE_VALUES:
            return "image"
        flavor: Any = posixpath
        if platform == "windows":
            import ntpath

            flavor = ntpath
        prefix = self._src("sys_prefix")
        if prefix:
            normal = flavor.normcase(flavor.normpath(prefix))
            if platform != "windows":
                if normal.startswith("/nix/store/"):
                    return "nix"
                if "Cellar" in normal.split("/")[:-1]:
                    return "brew"
            for channel, directories in (
                ("uv-tool", self._uv_tool_directories),
                ("uvx", self._uv_cache_directories),
                ("pipx", self._pipx_directories),
            ):
                for directory in directories(platform, flavor):
                    parts = self._below(directory, prefix, normal, flavor)
                    if parts is not None and self._is_channel_path(channel, parts):
                        return channel
        editable, installer = self._remember(("ash_record",), self._read_ash_record)
        return "source" if editable else installer

    @staticmethod
    def _is_channel_path(channel: str, parts: tuple[str, ...]) -> bool:
        if channel == "uvx":
            return len(parts) >= 2 and parts[0].startswith("environments-v")
        return bool(parts)

    def _below(
        self, directory: str, prefix: str, normal: str, flavor: Any
    ) -> Optional[tuple[str, ...]]:
        """The parts of the prefix under ``directory``, or None when it is not under it.

        ``normal`` is the prefix as written, normalized. The directory is compared with
        its links followed, and so is the prefix when it is not under the directory as
        written: an environment is made at the spelling of the directory it is made in,
        so a home reached through a link (or a Windows junction) puts the link's
        spelling in ``sys.prefix``.
        """
        if not flavor.isabs(directory):
            return None
        base = flavor.normcase(flavor.normpath(self._sources.realpath(directory)))
        separator = flavor.sep
        if base.endswith(separator):
            return None
        under = base + separator
        spelled = normal
        if not spelled.startswith(under):
            spelled = flavor.normcase(flavor.normpath(self._src("realpath", prefix)))
            if not spelled.startswith(under):
                return None
        return tuple(part for part in spelled[len(under) :].split(separator) if part)

    def _uv_tool_directories(self, platform: str, flavor: Any) -> Iterator[str]:
        explicit = self._sources.getenv("UV_TOOL_DIR")
        if explicit:
            yield explicit
        elif platform == "windows":
            appdata = self._sources.getenv("APPDATA")
            if appdata:
                yield flavor.join(appdata, "uv", "data", "tools")
        else:
            data = self._sources.getenv("XDG_DATA_HOME")
            if data:
                yield posixpath.join(data, "uv", "tools")
                return
            home = self._sources.home()
            if home:
                yield posixpath.join(home, ".local", "share", "uv", "tools")

    def _uv_cache_directories(self, platform: str, flavor: Any) -> Iterator[str]:
        explicit = self._sources.getenv("UV_CACHE_DIR")
        if explicit:
            yield explicit
        elif platform == "windows":
            local = self._sources.getenv("LOCALAPPDATA")
            if local:
                yield flavor.join(local, "uv", "cache")
        else:
            cache = self._sources.getenv("XDG_CACHE_HOME")
            if cache:
                yield posixpath.join(cache, "uv")
                return
            home = self._sources.home()
            if home:
                yield posixpath.join(home, ".cache", "uv")

    def _pipx_directories(self, platform: str, flavor: Any) -> Iterator[str]:
        explicit = self._sources.getenv("PIPX_HOME")
        if explicit:
            yield flavor.join(explicit, "venvs")
            return
        home = self._sources.home()
        if platform == "windows":
            if home:
                yield flavor.join(home, "pipx", "venvs")
                yield flavor.join(home, ".local", "pipx", "venvs")
            local = self._sources.getenv("LOCALAPPDATA")
            if local:
                yield flavor.join(local, "pipx", "pipx", "venvs")
        elif home:
            yield posixpath.join(home, ".local", "pipx", "venvs")
            yield posixpath.join(home, ".local", "share", "pipx", "venvs")
            if platform == "darwin":
                yield posixpath.join(
                    home, "Library", "Application Support", "pipx", "venvs"
                )

    def _read_ash_record(self) -> tuple[bool, str]:
        """``(editable, installer token)`` from ASH's installed metadata."""
        ash = self._src("distribution", _ASH_DISTRIBUTION)
        if ash is None:
            return (False, UNKNOWN)
        editable = _is_editable(ash.read_text("direct_url.json"))
        installer = (ash.read_text("INSTALLER") or "").strip().lower()
        return (editable, "pip" if installer in ("pip", "uv") else UNKNOWN)

    # ---- the whole reading -------------------------------------------------------

    def read(
        self, express_supported: Optional[Callable[[], bool]] = None
    ) -> HostReading:
        """One reading of every fact.

        ``express_supported`` is the caller's gate for the express path; without one
        the fact is ``unknown``, which is not a failure. No reader raises: a failure
        gives ``unknown`` and is recorded in ``HostReading.failed``.
        """
        failed: dict[str, str] = {}

        def attempt(fact: str, compute: Callable[[], str]) -> str:
            try:
                return compute()
            except Exception as exc:
                failed.setdefault(fact, _kind(exc))
                return UNKNOWN

        host = attempt("os", self._platform)

        runtime: Optional[_Runtime] = None
        try:
            runtime = self._runtime()
        except Exception as exc:
            failed.setdefault("polars_runtime", _kind(exc))
        level: str = UNKNOWN
        missing: tuple[str, ...] = ()
        try:
            level, missing = self._cpu_level(runtime)
        except Exception as exc:
            failed.setdefault("cpu_level", _kind(exc))

        python_text = UNKNOWN
        requires = UNKNOWN
        in_range = UNKNOWN
        try:
            python_text = self._python_version_text()
            requires, in_range = self._requires_python(python_text)
        except Exception as exc:
            failed.setdefault("python_in_range", _kind(exc))

        express = UNKNOWN
        if express_supported is not None:
            try:
                express = "yes" if express_supported() else "no"
            except Exception as exc:
                failed.setdefault("express_available", _kind(exc))

        return HostReading(
            os=host,
            host_os=host,
            os_release=attempt("os_release", self.os_release),
            arch=attempt("arch", self._arch),
            translation=attempt("translation", self._translation),
            cpu_level=level,
            polars_runtime=UNKNOWN if runtime is None else runtime.token,
            libc=attempt("libc", self.libc),
            python_in_range=in_range,
            python_build=attempt("python_build", self._python_build),
            install_channel=attempt("install_channel", self._install_channel),
            wsl=attempt("wsl", self._wsl),
            express_available=express,
            cpu_missing_flags=missing,
            python_version=python_text,
            requires_python=requires,
            failed=tuple(
                (name, failed[name]) for name in _READING_FACTS if name in failed
            ),
        )


# --------------------------------------------------------------------------------------
# The process-wide reader and the two small readers other modules call
# --------------------------------------------------------------------------------------

_PROCESS_READER: Optional[HostFactsReader] = None


def _process_reader() -> HostFactsReader:
    global _PROCESS_READER
    if _PROCESS_READER is None:
        _PROCESS_READER = HostFactsReader(Sources())
    return _PROCESS_READER


def _reader_for(sources: Optional[Sources]) -> HostFactsReader:
    return _process_reader() if sources is None else HostFactsReader(sources)


def read_host_facts(
    sources: Optional[Sources] = None,
    *,
    express_supported: Optional[Callable[[], bool]] = None,
) -> HostReading:
    """One reading of this host, or of the host ``sources`` describes.

    Without ``sources`` the process-wide reader is used, so what cannot change within
    a process is read once. With them, a new reader answers and nothing is kept.
    """
    return _reader_for(sources).read(express_supported=express_supported)


def read_os_release(sources: Optional[Sources] = None) -> str:
    """The recorded release text, ``unknown`` on any failure. Reads nothing else."""
    try:
        return _reader_for(sources).os_release()
    except Exception:
        return UNKNOWN


def read_libc(sources: Optional[Sources] = None) -> str:
    """The libc token, ``unknown`` on any failure. Reads nothing else."""
    try:
        return _reader_for(sources).libc()
    except Exception:
        return UNKNOWN
