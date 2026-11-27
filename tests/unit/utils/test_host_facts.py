"""The host-facts reader, each reader on planted inputs.

``utils/host_facts.py`` is the one place ASH reads the facts of the machine it runs
on. Every read goes through a ``Sources`` record of callables, so these tests plant
every input: the cpuinfo texts, the Windows constants, the fakes for ``sysctlbyname``
and ``IsWow64Process2``, os-release mappings, WSL ``osrelease`` strings, dist-info
``INSTALLER`` files and each install-channel prefix. A source a test did not plant
raises ``UnplantedRead``, which is not an ``Exception``, so a reader that reached for
the real host fails its test instead of answering from it. No test here reads the
machine it runs on.

What this file pins, beside each fact's table of cases:

* every token a reading holds is in the closed vocabulary spelled below, and a failed
  reader gives ``unknown``, never another token;
* a planted exception in any source turns facts into ``unknown`` and changes nothing
  else, and ``unknown`` matches none of the support rows the facts decide (the
  stand-in below encodes those rows);
* the one mapping onto the fields a support row matches on;
* what is read once per process and what is read on every call;
* plain versions, which the module compares itself, against what ``packaging`` says.

The processor facts (``cpu_level``, ``polars_runtime``) and their drift test against
the installed polars runtime are in ``test_host_facts_processor.py``.
"""

from __future__ import annotations

import ast
import dataclasses
import errno
import itertools
import sys
from collections import Counter
from importlib.metadata import PathDistribution
from pathlib import Path
from typing import Any, Callable, Collection, Iterable, Mapping, Optional

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from automated_security_helper.utils import host_facts
from automated_security_helper.utils.host_facts import (
    FACT_FIELDS,
    UNKNOWN,
    HostFactsReader,
    HostReading,
    Sources,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------------------
# Planting
# --------------------------------------------------------------------------------------


class UnplantedRead(BaseException):
    """A source the test did not plant was read: a read of the real host.

    Not an ``Exception``, so the readers' own ``except Exception`` cannot turn it into
    ``unknown`` and hide it.
    """


def _unplanted(name: str) -> Callable[..., object]:
    def read(*args: object, **kwargs: object) -> object:
        raise UnplantedRead(name)

    return read


#: Every source raises ``UnplantedRead``. A test names what a reader may read.
NOTHING = Sources(
    **{field.name: _unplanted(field.name) for field in dataclasses.fields(Sources)}
)


def planted(**sources: object) -> Sources:
    return dataclasses.replace(NOTHING, **sources)


def _raises(*args: object, **kwargs: object) -> object:
    raise RuntimeError("planted failure")


def canonical(name: str) -> str:
    return name.lower().replace("_", "-")


#: The text a default runtime (32 or 64) carries, as the 1.44 wheels write it.
DEFAULT_FLAGS_TEXT = (
    'BUILD_FEATURE_FLAGS = "+sse3,+ssse3,+sse4.1,+sse4.2,+popcnt,+cmpxchg16b,'
    '+avx,+avx2,+fma,+bmi1,+bmi2,+lzcnt,+pclmulqdq,+movbe"\n'
)
#: The text the compatibility runtime carries.
COMPAT_FLAGS_TEXT = (
    'BUILD_FEATURE_FLAGS = "+sse3,+ssse3,+sse4.1,+sse4.2,+popcnt,+cmpxchg16b"\n'
)
RUNTIME_INIT_TEXT = (
    "try:\n"
    "    from .build_feature_flags import BUILD_FEATURE_FLAGS\n"
    "except ImportError:\n"
    '    BUILD_FEATURE_FLAGS = ""\n'
)


_SITES = itertools.count()


class Site:
    """A directory of planted distributions that a planted ``distribution`` source reads.

    Each site is a new directory under ``root``, so one test can build several hosts.
    """

    def __init__(self, root: Path) -> None:
        self.root = root / f"site-{next(_SITES)}"
        self.root.mkdir(parents=True)
        self.distributions: dict[str, PathDistribution] = {}
        self.lookups: list[str] = []

    def add(
        self,
        name: str,
        version: str,
        *,
        headers: str = "",
        files: Optional[Mapping[str, str]] = None,
        installer: Optional[str] = None,
        direct_url: Optional[str] = None,
    ) -> PathDistribution:
        info = self.root / f"{name.replace('-', '_')}-{version}.dist-info"
        info.mkdir(parents=True)
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n{headers}",
            encoding="utf-8",
        )
        record = []
        for relative, text in (files or {}).items():
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            record.append(f"{relative},,")
        if record:
            (info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")
        if installer is not None:
            (info / "INSTALLER").write_text(installer + "\n", encoding="utf-8")
        if direct_url is not None:
            (info / "direct_url.json").write_text(direct_url, encoding="utf-8")
        distribution = PathDistribution(info)
        self.distributions[canonical(name)] = distribution
        return distribution

    def add_runtime(
        self,
        selector: str,
        flags_text: Optional[str],
        *,
        version: str = "1.44.2",
        listed: bool = True,
    ) -> PathDistribution:
        """A polars runtime; ``flags_text`` None leaves the flags file out, and
        ``listed`` False leaves it out of the RECORD while it stays on disk."""
        package = f"_polars_runtime_{selector}"
        files = {f"{package}/__init__.py": RUNTIME_INIT_TEXT}
        if flags_text is not None and listed:
            files[f"{package}/build_feature_flags.py"] = flags_text
        distribution = self.add(f"polars-runtime-{selector}", version, files=files)
        if flags_text is not None and not listed:
            (self.root / package / "build_feature_flags.py").write_text(
                flags_text, encoding="utf-8"
            )
        return distribution

    def add_ash(
        self,
        *,
        requires_python: Optional[str] = "<3.15,>=3.11",
        installer: Optional[str] = "uv",
        direct_url: Optional[str] = None,
    ) -> PathDistribution:
        headers = (
            "" if requires_python is None else f"Requires-Python: {requires_python}\n"
        )
        return self.add(
            "automated-security-helper",
            "3.8.0",
            headers=headers,
            installer=installer,
            direct_url=direct_url,
        )

    def lookup(self, name: str) -> Optional[PathDistribution]:
        self.lookups.append(canonical(name))
        return self.distributions.get(canonical(name))


def polars_site(
    root: Path,
    *,
    runtimes: Optional[Mapping[str, Optional[str]]] = None,
    polars: Optional[str] = "1.44.2",
    ash: bool = True,
) -> Site:
    """polars with the locked runtime (32) by default, and ASH's own distribution."""
    site = Site(root)
    if polars is not None:
        site.add("polars", polars)
    for selector, text in (
        {"32": DEFAULT_FLAGS_TEXT} if runtimes is None else runtimes
    ).items():
        site.add_runtime(selector, text, version=polars or "1.44.2")
    if ash:
        site.add_ash()
    return site


def cpuinfo(flags: str, *, later_flags: Optional[str] = None) -> str:
    """A /proc/cpuinfo text of a two-processor machine in the kernel's layout."""

    def block(index: int, line: str) -> str:
        return (
            f"processor\t: {index}\n"
            "vendor_id\t: PlantedVendor\n"
            "cpu family\t: 6\n"
            "model name\t: Planted CPU @ 2.50GHz\n"
            "cpu MHz\t\t: 2500.000\n"
            f"flags\t\t: {line}\n"
            "bugs\t\t: cpu_meltdown spectre_v1\n"
            "address sizes\t: 46 bits physical, 48 bits virtual\n"
            "power management:\n"
        )

    second = flags if later_flags is None else later_flags
    return block(0, flags) + "\n" + block(1, second)


#: An AVX2-class Intel part with the kernel's spellings (pni, sse4_1, abm, cx16).
SKYLAKE_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
    "dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm "
    "constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid "
    "aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 "
    "xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave "
    "avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb pti ssbd ibrs ibpb "
    "stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle "
    "avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt intel_pt xsaveopt "
    "xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window "
    "hwp_epp md_clear flush_l1d"
)

#: Spelled in this file, not read from the module: the closed vocabulary of each fact a
#: host reader decides, plus ``unknown`` for a reader that failed.
VOCABULARY = {
    "os": {"linux", "darwin", "windows", "other", "unknown"},
    "host_os": {"linux", "darwin", "windows", "other", "unknown"},
    "arch": {"amd64", "arm64", "other", "unknown"},
    "translation": {"native", "rosetta", "x64-on-arm64", "unknown"},
    "cpu_level": {"full", "compat-only", "below-compat", "n/a", "unknown"},
    "polars_runtime": {"runtime-32", "runtime-64", "compat", "absent", "unknown"},
    "libc": {"glibc", "musl", "n/a", "unknown"},
    "python_in_range": {"yes", "no", "unknown"},
    "python_build": {"standard", "free-threaded", "other-implementation", "unknown"},
    "install_channel": {
        "uv-tool",
        "uvx",
        "pipx",
        "pip",
        "brew",
        "nix",
        "image",
        "source",
        "unknown",
    },
    "wsl": {"wsl2", "wsl1", "no", "n/a", "unknown"},
    "express_available": {"yes", "no", "unknown"},
}

#: The fields a support row matches on that a host reader fills, in their order.
SUPPORT_FIELDS = [
    "os",
    "host_os",
    "os_release",
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
]


def assert_closed(reading: HostReading) -> None:
    for fact, allowed in VOCABULARY.items():
        assert getattr(reading, fact) in allowed, (fact, getattr(reading, fact))


def read(sources: Sources, *, express: Optional[bool] = True) -> HostReading:
    """One reading through a fresh reader; every token is checked against the vocabulary."""
    gate: Optional[Callable[[], bool]] = None if express is None else (lambda: express)
    reading = HostFactsReader(sources).read(express_supported=gate)
    assert_closed(reading)
    return reading


def stand_in_matches(reading: HostReading) -> list[str]:
    """The ids of the support rows that the facts of ``reading`` alone decide.

    A stand-in for the support register's evaluation, with the seven rows that match
    on facts this module reads: the processor against the runtime in use, binary
    translation, an unsupported operating system or architecture, and an interpreter
    outside ASH's range. ``unknown`` is in none of them, which is the property the
    register has by construction.
    """
    hits = []
    runtime = reading.polars_runtime
    level = reading.cpu_level
    if reading.arch == "amd64" and (
        (
            runtime in ("runtime-32", "runtime-64")
            and level in ("compat-only", "below-compat")
        )
        or (runtime == "compat" and level == "below-compat")
    ):
        hits.append("host.cpu.below-polars-runtime")
    if runtime == "compat" and level in ("full", "compat-only"):
        hits.append("host.cpu.polars-compat-runtime")
    if reading.host_os == "darwin" and reading.translation == "rosetta":
        hits.append("host.translation.rosetta")
    if reading.host_os == "windows" and reading.translation == "x64-on-arm64":
        hits.append("host.translation.x64-on-arm64")
    if reading.host_os == "other":
        hits.append("host.os.other")
    if reading.arch == "other":
        hits.append("host.arch.other")
    if reading.python_in_range == "no":
        hits.append("host.python.outside-requires")
    return hits


# --------------------------------------------------------------------------------------
# Planted hosts
# --------------------------------------------------------------------------------------

LINUX_PREFIX = "/home/u/.local/share/uv/tools/automated-security-helper"


def linux_host(
    root: Path,
    *,
    site: Optional[Site] = None,
    cpuinfo_text: Optional[str] = None,
    osrelease: str = "6.8.0-45-generic\n",
    env: Optional[Mapping[str, str]] = None,
    prefix: str = LINUX_PREFIX,
) -> Sources:
    """A supported Linux host: Ubuntu 24.04 on an AVX2-class x86-64 part, glibc, uv tool."""
    site = site if site is not None else polars_site(root)
    files = {
        "/proc/cpuinfo": cpuinfo(SKYLAKE_FLAGS)
        if cpuinfo_text is None
        else cpuinfo_text,
        "/proc/sys/kernel/osrelease": osrelease,
    }
    environment = dict(env or {})

    def read_text(path: str, limit: int) -> str:
        if path not in files:
            raise FileNotFoundError(errno.ENOENT, path)
        return files[path][:limit]

    return planted(
        sys_platform=lambda: "linux",
        machine=lambda: "x86_64",
        pointer_bits=lambda: 64,
        read_text=read_text,
        freedesktop_os_release=lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"},
        libc_version=lambda: "glibc 2.39",
        platform_tags=lambda: iter(
            ["linux_x86_64", "manylinux_2_39_x86_64", "manylinux_2_38_x86_64"]
        ),
        distribution=site.lookup,
        getenv=environment.get,
        sys_prefix=lambda: prefix,
        realpath=lambda path: path,
        home=lambda: "/home/u",
        python_version=lambda: (3, 12, 15, "final", 0),
        implementation_name=lambda: "cpython",
        gil_disabled=lambda: False,
        polars_plr_injected=lambda: False,
    )


MAC_HASWELL_STRINGS = {
    "machdep.cpu.features": (
        "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE36 CLFSH "
        "DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE SSE3 PCLMULQDQ DTES64 MON DSCPL VMX "
        "SMX EST TM2 SSSE3 FMA CX16 TPR PDCM SSE4.1 SSE4.2 x2APIC MOVBE POPCNT AES PCID "
        "XSAVE OSXSAVE SEGLIM64 TSCTMR AVX1.0 RDRAND F16C"
    ),
    "machdep.cpu.leaf7_features": (
        "RDWRFSGS TSC_THREAD_OFFSET BMI1 AVX2 SMEP BMI2 ERMS INVPCID FPU_CSDS RDSEED "
        "ADX SMAP CLFSOPT IPT MDCLEAR IBRS STIBP L1DF ACAPMSR SSBD"
    ),
    "machdep.cpu.extfeatures": "SYSCALL XD 1GBPAGE EM64T LAHF LZCNT PREFETCHW RDTSCP TSCI",
}


def macos_host(
    root: Path,
    *,
    site: Optional[Site] = None,
    machine: str = "x86_64",
    translated: Any = None,
    strings: Optional[Mapping[str, Any]] = None,
    version: str = "15.1",
    prefix: str = "/Users/u/.local/share/uv/tools/automated-security-helper",
    env: Optional[Mapping[str, str]] = None,
) -> Sources:
    """An Intel Mac on macOS 15.1; ``translated`` None is the absent sysctl name."""
    site = site if site is not None else polars_site(root)
    answers = dict(MAC_HASWELL_STRINGS if strings is None else strings)
    environment = dict(env or {})

    def sysctl_int(name: str) -> int:
        if name != "sysctl.proc_translated":
            raise UnplantedRead(name)
        if translated is None:
            raise OSError(errno.ENOENT, "No such file or directory")
        if isinstance(translated, BaseException):
            raise translated
        return int(translated)

    def sysctl_str(name: str) -> str:
        if name not in answers:
            raise OSError(errno.ENOENT, "No such file or directory")
        answer = answers[name]
        if isinstance(answer, BaseException):
            raise answer
        return str(answer)

    return planted(
        sys_platform=lambda: "darwin",
        machine=lambda: machine,
        pointer_bits=lambda: 64,
        mac_version=lambda: version,
        sysctl_int=sysctl_int,
        sysctl_str=sysctl_str,
        distribution=site.lookup,
        getenv=environment.get,
        sys_prefix=lambda: prefix,
        realpath=lambda path: path,
        home=lambda: "/Users/u",
        python_version=lambda: (3, 12, 15, "final", 0),
        implementation_name=lambda: "cpython",
        gil_disabled=lambda: False,
        polars_plr_injected=lambda: False,
    )


#: IsProcessorFeaturePresent constants, as the documentation lists them.
PF_SSE3, PF_CX16, PF_SSSE3, PF_SSE4_1, PF_SSE4_2, PF_AVX, PF_AVX2, PF_BMI2 = (
    13,
    14,
    36,
    37,
    38,
    39,
    40,
    60,
)
ALL_PRESENT = frozenset(
    {PF_SSE3, PF_CX16, PF_SSSE3, PF_SSE4_1, PF_SSE4_2, PF_AVX, PF_AVX2, PF_BMI2}
)
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_MACHINE_I386 = 0x014C

WINDOWS_PREFIX = (
    "C:\\Users\\u\\AppData\\Roaming\\uv\\data\\tools\\automated-security-helper"
)


def windows_host(
    root: Path,
    *,
    site: Optional[Site] = None,
    build: int = 26100,
    present: Collection[int] = ALL_PRESENT,
    wow64: Any = (0, IMAGE_FILE_MACHINE_AMD64),
    platform_name: str = "win-amd64",
    asked: Optional[list[int]] = None,
    prefix: str = WINDOWS_PREFIX,
    env: Optional[Mapping[str, str]] = None,
) -> Sources:
    """Windows 11 24H2 on an x64 part. ``asked`` collects the constants that were read."""
    site = site if site is not None else polars_site(root)
    environment = {
        "APPDATA": "C:\\Users\\u\\AppData\\Roaming",
        "LOCALAPPDATA": "C:\\Users\\u\\AppData\\Local",
        **(env or {}),
    }

    def feature_present(constant: int) -> bool:
        if asked is not None:
            asked.append(constant)
        return constant in present

    def wow64_machines() -> tuple[int, int]:
        if isinstance(wow64, BaseException):
            raise wow64
        process_machine, native_machine = wow64
        return (process_machine, native_machine)

    return planted(
        sys_platform=lambda: "win32",
        sysconfig_platform=lambda: platform_name,
        pointer_bits=lambda: 64,
        windows_version=lambda: (10, 0, build),
        windows_feature_present=feature_present,
        wow64_machines=wow64_machines,
        distribution=site.lookup,
        getenv=environment.get,
        sys_prefix=lambda: prefix,
        realpath=lambda path: path,
        home=lambda: "C:\\Users\\u",
        python_version=lambda: (3, 12, 15, "final", 0),
        implementation_name=lambda: "cpython",
        gil_disabled=lambda: False,
        polars_plr_injected=lambda: False,
    )


# --------------------------------------------------------------------------------------
# The baselines decide every fact
# --------------------------------------------------------------------------------------


def test_the_supported_linux_host_reads_as_the_reference_environment(tmp_path):
    reading = read(linux_host(tmp_path))
    assert host_facts.fact_tokens(reading) == {
        "os": "linux",
        "host_os": "linux",
        "os_release": "ubuntu 24.04",
        "arch": "amd64",
        "translation": "native",
        "cpu_level": "full",
        "polars_runtime": "runtime-32",
        "libc": "glibc",
        "python_in_range": "yes",
        "python_build": "standard",
        "install_channel": "uv-tool",
        "wsl": "no",
        "express_available": "yes",
    }
    assert reading.failed == ()
    assert reading.cpu_missing_flags == ()
    assert reading.python_version == "3.12.15"
    assert reading.requires_python == ">=3.11,<3.15"
    assert stand_in_matches(reading) == []


def test_the_supported_macos_host_reads_as_a_native_intel_mac(tmp_path):
    reading = read(macos_host(tmp_path))
    assert host_facts.fact_tokens(reading) == {
        "os": "darwin",
        "host_os": "darwin",
        "os_release": "macos 15.1",
        "arch": "amd64",
        "translation": "native",
        "cpu_level": "full",
        "polars_runtime": "runtime-32",
        "libc": "n/a",
        "python_in_range": "yes",
        "python_build": "standard",
        "install_channel": "uv-tool",
        "wsl": "n/a",
        "express_available": "yes",
    }
    assert reading.failed == ()
    assert stand_in_matches(reading) == []


def test_the_supported_windows_host_reads_as_a_native_x64_machine(tmp_path):
    reading = read(windows_host(tmp_path), express=False)
    assert host_facts.fact_tokens(reading) == {
        "os": "windows",
        "host_os": "windows",
        "os_release": "windows 10.0.26100",
        "arch": "amd64",
        "translation": "native",
        "cpu_level": "full",
        "polars_runtime": "runtime-32",
        "libc": "n/a",
        "python_in_range": "yes",
        "python_build": "standard",
        "install_channel": "uv-tool",
        "wsl": "n/a",
        "express_available": "no",
    }
    assert reading.failed == ()
    assert stand_in_matches(reading) == []


# --------------------------------------------------------------------------------------
# The vocabulary and the one mapping
# --------------------------------------------------------------------------------------


def test_the_module_vocabulary_is_the_closed_vocabulary_spelled_here():
    assert {
        name: set(tokens) for name, tokens in host_facts.TOKENS.items()
    } == VOCABULARY


def test_the_fact_fields_are_the_support_fields_in_their_order():
    assert list(FACT_FIELDS) == SUPPORT_FIELDS


def test_the_reading_carries_exactly_those_fields_and_its_details():
    names = [field.name for field in dataclasses.fields(HostReading)]
    assert names[: len(SUPPORT_FIELDS)] == SUPPORT_FIELDS
    assert names[len(SUPPORT_FIELDS) :] == [
        "cpu_missing_flags",
        "python_version",
        "requires_python",
        "failed",
    ]


def test_fact_tokens_is_the_one_mapping_onto_the_fields_a_support_row_matches_on(
    tmp_path,
):
    reading = read(linux_host(tmp_path))
    mapping = host_facts.fact_tokens(reading)
    assert list(mapping) == SUPPORT_FIELDS
    assert all(mapping[name] == getattr(reading, name) for name in SUPPORT_FIELDS)
    # What a notice names beside the tokens, and the failures, are not facts a row matches.
    assert not {"failed", "cpu_missing_flags", "python_version"} & set(mapping)


def test_a_reading_is_frozen_and_compares_by_value(tmp_path):
    first = read(linux_host(tmp_path))
    second = read(linux_host(tmp_path))
    assert first == second
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.os = "windows"  # type: ignore[misc]


# --------------------------------------------------------------------------------------
# os and host_os
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("platform_name", "expected"),
    [
        ("linux", "linux"),
        ("linux2", "linux"),
        ("cygwin", "other"),
        ("msys", "other"),
        ("freebsd14", "other"),
        ("emscripten", "other"),
        ("android", "other"),
        ("ios", "other"),
        ("", "other"),
    ],
)
def test_os_and_host_os_come_from_sys_platform(tmp_path, platform_name, expected):
    sources = dataclasses.replace(
        linux_host(tmp_path), sys_platform=lambda: platform_name
    )
    reading = read(sources)
    assert (reading.os, reading.host_os) == (expected, expected)


def test_darwin_and_win32_are_the_other_two_platforms(tmp_path):
    assert read(macos_host(tmp_path)).os == "darwin"
    assert read(windows_host(tmp_path / "w")).os == "windows"


def test_an_unrecognized_platform_matches_the_unsupported_os_row_and_only_it(tmp_path):
    sources = dataclasses.replace(
        linux_host(tmp_path), sys_platform=lambda: "freebsd14"
    )
    reading = read(sources)
    assert reading.libc == "n/a" and reading.wsl == "n/a"
    assert reading.translation == UNKNOWN
    assert stand_in_matches(reading) == ["host.os.other"]


# --------------------------------------------------------------------------------------
# arch
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("machine", "bits", "expected"),
    [
        ("x86_64", 64, "amd64"),
        ("amd64", 64, "amd64"),
        ("AMD64", 64, "amd64"),
        ("aarch64", 64, "arm64"),
        ("arm64", 64, "arm64"),
        ("armv7l", 32, "other"),
        ("i686", 32, "other"),
        ("i386", 32, "other"),
        ("ppc64le", 64, "other"),
        ("s390x", 64, "other"),
        ("riscv64", 64, "other"),
        # A 32-bit interpreter on a 64-bit kernel still names the kernel's machine.
        ("x86_64", 32, "other"),
        ("aarch64", 32, "other"),
        ("", 64, "unknown"),
        ("  ", 64, "unknown"),
    ],
)
def test_posix_arch_is_the_machine_and_the_pointer_size(
    tmp_path, machine, bits, expected
):
    sources = dataclasses.replace(
        linux_host(tmp_path), machine=lambda: machine, pointer_bits=lambda: bits
    )
    assert read(sources).arch == expected


@pytest.mark.parametrize(
    ("platform_name", "bits", "expected"),
    [
        ("win-amd64", 64, "amd64"),
        ("win-arm64", 64, "arm64"),
        ("win32", 32, "other"),
        ("win-arm32", 32, "other"),
        ("mingw_x86_64", 64, "amd64"),
        ("win-amd64", 32, "other"),
        ("", 64, "unknown"),
    ],
)
def test_windows_arch_is_the_interpreters_own_platform(
    tmp_path, platform_name, bits, expected
):
    sources = dataclasses.replace(
        windows_host(tmp_path, platform_name=platform_name), pointer_bits=lambda: bits
    )
    # The processor facts are not under test here; a Windows 11 host answers them.
    assert read(sources).arch == expected


def test_posix_arch_never_reads_the_windows_platform_string(tmp_path):
    # ``sysconfig_platform`` stays unplanted: reading it would raise UnplantedRead.
    assert read(linux_host(tmp_path)).arch == "amd64"


def test_windows_arch_never_asks_for_uname(tmp_path):
    # ``machine`` stays unplanted: ``os.uname`` does not exist on Windows.
    assert read(windows_host(tmp_path)).arch == "amd64"


def test_macos_arm64_is_native_and_has_no_processor_level(tmp_path):
    sources = macos_host(tmp_path, machine="arm64", translated=0)
    reading = read(sources)
    assert (reading.arch, reading.translation, reading.cpu_level) == (
        "arm64",
        "native",
        "n/a",
    )


# --------------------------------------------------------------------------------------
# translation
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("translated", "expected"),
    [
        (1, "rosetta"),
        (0, "native"),
        # The name is absent on Intel Macs and on older macOS: the process is native.
        (None, "native"),
        (2, "unknown"),
        (-1, "unknown"),
        (OSError(errno.EPERM, "Operation not permitted"), "unknown"),
        (OSError(errno.EINVAL, "Invalid argument"), "unknown"),
    ],
)
def test_macos_translation_is_the_proc_translated_sysctl(
    tmp_path, translated, expected
):
    reading = read(macos_host(tmp_path, translated=translated))
    assert reading.translation == expected


def test_a_translated_x86_process_is_a_rosetta_reading_with_its_row(tmp_path):
    reading = read(macos_host(tmp_path, translated=1))
    assert (reading.os, reading.arch, reading.translation) == (
        "darwin",
        "amd64",
        "rosetta",
    )
    assert stand_in_matches(reading) == ["host.translation.rosetta"]


@pytest.mark.parametrize(
    ("wow64", "expected"),
    [
        ((0, IMAGE_FILE_MACHINE_AMD64), "native"),
        ((0, IMAGE_FILE_MACHINE_ARM64), "native"),
        ((IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64), "x64-on-arm64"),
        # 32-bit x86 on 64-bit x86 Windows is WOW64, which translates nothing.
        ((IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64), "native"),
        # 32-bit x86 emulated on arm64 has no token: unknown, never x64-on-arm64.
        ((IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_ARM64), "unknown"),
        ((0x1234, 0x5678), "unknown"),
        # Windows before 10 1511 has no IsWow64Process2.
        (AttributeError("IsWow64Process2"), "unknown"),
        (OSError(errno.EINVAL, "failed"), "unknown"),
    ],
)
def test_windows_translation_is_the_two_machines_of_iswow64process2(
    tmp_path, wow64, expected
):
    reading = read(windows_host(tmp_path, wow64=wow64))
    assert reading.translation == expected


def test_an_x64_process_on_an_arm64_host_matches_the_emulation_row(tmp_path):
    reading = read(
        windows_host(
            tmp_path, wow64=(IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64)
        )
    )
    assert reading.arch == "amd64"
    assert stand_in_matches(reading) == ["host.translation.x64-on-arm64"]


def test_linux_translation_is_native_with_no_read(tmp_path):
    # sysctl_int and wow64_machines stay unplanted on the Linux host.
    assert read(linux_host(tmp_path)).translation == "native"


# --------------------------------------------------------------------------------------
# os_release (recorded only)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mapping", "expected"),
    [
        ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "ubuntu 24.04"),
        ({"ID": "debian", "VERSION_ID": "12"}, "debian 12"),
        ({"ID": "alpine", "VERSION_ID": "3.20.3"}, "alpine 3.20.3"),
        (
            {
                "ID": "amzn",
                "VERSION_ID": "2023",
                "PRETTY_NAME": "Amazon Linux 2023.12.20261120",
            },
            "amzn 2023",
        ),
        # A rolling release names no version.
        ({"ID": "arch", "PRETTY_NAME": "Arch Linux"}, "arch"),
        ({"ID": "Ubuntu", "VERSION_ID": "24.04"}, "ubuntu 24.04"),
        # The text is host data and goes into a notice: only a plain token run is kept.
        ({"ID": "ubuntu\n", "VERSION_ID": "24.04 LTS (Noble)"}, "ubuntu 24.04"),
        ({"ID": "<script>alert(1)</script>", "VERSION_ID": "1"}, "unknown"),
        ({"ID": "\u00fcbuntu", "VERSION_ID": "1"}, "unknown"),
        ({"ID": "x" * 80, "VERSION_ID": "1"}, "x" * 32 + " 1"),
        ({"PRETTY_NAME": "Mystery"}, "unknown"),
        ({}, "unknown"),
    ],
)
def test_linux_release_is_the_id_and_version_from_os_release(
    tmp_path, mapping, expected
):
    sources = dataclasses.replace(
        linux_host(tmp_path), freedesktop_os_release=lambda: mapping
    )
    assert read(sources).os_release == expected


def test_a_missing_os_release_file_reads_unknown_and_is_a_failure(tmp_path):
    def missing() -> Mapping[str, str]:
        raise FileNotFoundError(errno.ENOENT, "/etc/os-release")

    reading = read(
        dataclasses.replace(linux_host(tmp_path), freedesktop_os_release=missing)
    )
    assert reading.os_release == UNKNOWN
    assert ("os_release", "FileNotFoundError") in reading.failed


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("15.1", "macos 15.1"),
        ("15.1.1", "macos 15.1.1"),
        ("10.16", "macos 10.16"),
        ("", "unknown"),
        ("sequoia", "unknown"),
        ("15.1 beta", "macos 15.1"),
    ],
)
def test_macos_release_is_the_mac_ver_version(tmp_path, version, expected):
    assert read(macos_host(tmp_path, version=version)).os_release == expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ((10, 0, 26100), "windows 10.0.26100"),
        ((10, 0, 19045), "windows 10.0.19045"),
        ((6, 3, 9600), "windows 6.3.9600"),
    ],
)
def test_windows_release_is_the_version_triple(tmp_path, version, expected):
    sources = dataclasses.replace(
        windows_host(tmp_path), windows_version=lambda: version
    )
    assert read(sources).os_release == expected


def test_the_release_is_recorded_not_matched(tmp_path):
    # Whatever the release, no support row matches on it.
    for mapping in (
        {"ID": "ubuntu", "VERSION_ID": "10"},
        {"ID": "rhel", "VERSION_ID": "6"},
    ):
        sources = dataclasses.replace(
            linux_host(tmp_path), freedesktop_os_release=lambda m=mapping: m
        )
        assert stand_in_matches(read(sources)) == []


# --------------------------------------------------------------------------------------
# wsl
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("osrelease", "expected"),
    [
        ("5.15.153.1-microsoft-standard-WSL2\n", "wsl2"),
        ("6.6.87.2-microsoft-standard-WSL2\n", "wsl2"),
        ("5.10.16.3-Microsoft-standard-WSL2", "wsl2"),
        ("4.4.0-19041-Microsoft\n", "wsl1"),
        ("4.4.0-22621-Microsoft\n", "wsl1"),
        ("4.4.0-17763-microsoft", "wsl1"),
        ("6.8.0-45-generic\n", "no"),
        ("6.12.115-140.210.amzn2023.x86_64\n", "no"),
        ("5.14.0-427.el9.x86_64\n", "no"),
        ("", "unknown"),
        ("   \n", "unknown"),
    ],
)
def test_wsl_is_read_from_the_kernel_release_string(tmp_path, osrelease, expected):
    assert read(linux_host(tmp_path, osrelease=osrelease)).wsl == expected


def test_an_unreadable_kernel_release_reads_unknown(tmp_path):
    sources = linux_host(tmp_path)
    inner = sources.read_text

    def read_text(path: str, limit: int) -> str:
        if path == "/proc/sys/kernel/osrelease":
            raise PermissionError(errno.EACCES, path)
        return inner(path, limit)

    reading = read(dataclasses.replace(sources, read_text=read_text))
    assert reading.wsl == UNKNOWN
    assert reading.cpu_level == "full"
    assert ("wsl", "PermissionError") in reading.failed


def test_wsl_is_not_applicable_off_linux_and_reads_nothing_there(tmp_path):
    assert read(macos_host(tmp_path)).wsl == "n/a"
    assert read(windows_host(tmp_path / "w")).wsl == "n/a"


# --------------------------------------------------------------------------------------
# libc
# --------------------------------------------------------------------------------------


def test_glibc_is_answered_by_the_c_library_and_reads_no_tags(tmp_path):
    sources = dataclasses.replace(
        linux_host(tmp_path), platform_tags=_unplanted("platform_tags")
    )
    assert read(sources).libc == "glibc"


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        # packaging 26 yields the plain linux tag first; 24 yields it last.
        (["linux_x86_64", "manylinux_2_34_x86_64", "manylinux_2_17_x86_64"], "glibc"),
        (["manylinux_2_28_x86_64", "manylinux2014_x86_64", "linux_x86_64"], "glibc"),
        (["linux_x86_64", "musllinux_1_2_x86_64", "musllinux_1_1_x86_64"], "musl"),
        (["musllinux_1_2_aarch64", "linux_aarch64"], "musl"),
        (["linux_x86_64"], "unknown"),
        ([], "unknown"),
        (["any"], "unknown"),
    ],
)
def test_libc_falls_back_to_the_platform_tags_when_the_c_library_is_silent(
    tmp_path, tags, expected
):
    def silent() -> str:
        raise ValueError("unrecognized configuration name")

    sources = dataclasses.replace(
        linux_host(tmp_path), libc_version=silent, platform_tags=lambda: iter(tags)
    )
    assert read(sources).libc == expected


def test_a_c_library_that_is_not_glibc_falls_back_to_the_tags(tmp_path):
    sources = dataclasses.replace(
        linux_host(tmp_path),
        libc_version=lambda: "uClibc 1.0",
        platform_tags=lambda: iter(["linux_x86_64", "musllinux_1_2_x86_64"]),
    )
    assert read(sources).libc == "musl"


def test_the_tag_scan_is_bounded(tmp_path):
    def endless() -> Iterable[str]:
        while True:
            yield "linux_x86_64"

    def silent() -> str:
        raise ValueError("no such name")

    sources = dataclasses.replace(
        linux_host(tmp_path), libc_version=silent, platform_tags=endless
    )
    assert read(sources).libc == UNKNOWN


def test_a_manylinux_tag_beyond_the_scan_bound_is_not_read(tmp_path):
    tags = ["linux_x86_64"] * 64 + ["manylinux_2_17_x86_64"]

    def silent() -> str:
        raise ValueError("no such name")

    sources = dataclasses.replace(
        linux_host(tmp_path), libc_version=silent, platform_tags=lambda: iter(tags)
    )
    assert read(sources).libc == UNKNOWN


def test_a_failing_tag_source_reads_unknown_and_is_a_failure(tmp_path):
    def silent() -> str:
        raise ValueError("no such name")

    sources = dataclasses.replace(
        linux_host(tmp_path), libc_version=silent, platform_tags=_raises
    )
    reading = read(sources)
    assert reading.libc == UNKNOWN
    assert ("libc", "RuntimeError") in reading.failed


def test_libc_is_not_applicable_off_linux(tmp_path):
    # libc_version and platform_tags stay unplanted there.
    assert read(macos_host(tmp_path)).libc == "n/a"
    assert read(windows_host(tmp_path / "w")).libc == "n/a"


# --------------------------------------------------------------------------------------
# python_in_range, python_build
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "requires", "in_range", "text"),
    [
        ((3, 12, 15, "final", 0), "<3.15,>=3.11", "yes", "3.12.15"),
        ((3, 11, 0, "final", 0), "<3.15,>=3.11", "yes", "3.11.0"),
        ((3, 14, 3, "final", 0), ">=3.11,<3.15", "yes", "3.14.3"),
        ((3, 10, 14, "final", 0), "<3.15,>=3.11", "no", "3.10.14"),
        ((3, 15, 0, "final", 0), "<3.15,>=3.11", "no", "3.15.0"),
        # A pre-release of the excluded upper bound is outside the range too.
        ((3, 15, 0, "alpha", 1), "<3.15,>=3.11", "no", "3.15.0a1"),
        ((3, 15, 0, "candidate", 2), ">=3.11,<3.15", "no", "3.15.0rc2"),
        ((3, 14, 0, "beta", 3), ">=3.11,<3.15", "yes", "3.14.0b3"),
    ],
)
def test_python_in_range_is_the_version_against_the_installed_requires_python(
    tmp_path, version, requires, in_range, text
):
    site = polars_site(tmp_path, ash=False)
    site.add_ash(requires_python=requires)
    sources = dataclasses.replace(
        linux_host(tmp_path, site=site), python_version=lambda: version
    )
    reading = read(sources)
    assert (reading.python_in_range, reading.python_version) == (in_range, text)


def test_requires_python_is_recorded_lower_bound_first(tmp_path):
    site = polars_site(tmp_path, ash=False)
    site.add_ash(requires_python="<3.15, >=3.11")
    reading = read(linux_host(tmp_path, site=site))
    assert reading.requires_python == ">=3.11,<3.15"


def test_a_source_checkout_with_no_metadata_reads_unknown_but_still_names_python(
    tmp_path,
):
    site = polars_site(tmp_path, ash=False)
    reading = read(linux_host(tmp_path, site=site))
    assert reading.python_in_range == UNKNOWN
    assert reading.requires_python == UNKNOWN
    assert reading.python_version == "3.12.15"
    assert reading.failed == ()


def test_metadata_with_no_requires_python_reads_unknown(tmp_path):
    site = polars_site(tmp_path, ash=False)
    site.add_ash(requires_python=None)
    assert read(linux_host(tmp_path, site=site)).python_in_range == UNKNOWN


@pytest.mark.parametrize(
    "requires",
    ["not a specifier", ">=3.11,,<", "=>3.11", ">=3.11 and <3.15", "\u2265 3.11"],
)
def test_a_malformed_requires_python_reads_unknown(tmp_path, requires):
    site = polars_site(tmp_path, ash=False)
    site.add_ash(requires_python=requires)
    reading = read(linux_host(tmp_path, site=site))
    assert reading.python_in_range == UNKNOWN
    assert stand_in_matches(reading) == []


@pytest.mark.parametrize(
    ("implementation", "gil_disabled", "expected"),
    [
        ("cpython", False, "standard"),
        ("cpython", True, "free-threaded"),
        ("pypy", False, "other-implementation"),
        ("graalpy", False, "other-implementation"),
        ("pypy", True, "other-implementation"),
    ],
)
def test_python_build_is_the_implementation_and_the_gil_build(
    tmp_path, implementation, gil_disabled, expected
):
    sources = dataclasses.replace(
        linux_host(tmp_path),
        implementation_name=lambda: implementation,
        gil_disabled=lambda: gil_disabled,
    )
    assert read(sources).python_build == expected


# --------------------------------------------------------------------------------------
# Plain versions are read here, without packaging
# --------------------------------------------------------------------------------------
#
# A version made only of digits and dots is compared by the module itself, and any other
# text goes to ``packaging``, so every reading and every error stays what it was. The
# three functions below are what ``packaging`` says, written out with no help from the
# module, and each fast path is held to them.


def packaging_polars_in_range(version: str) -> bool:
    low = ".".join(str(part) for part in host_facts.POLARS_MIN_VERSION)
    high = ".".join(str(part) for part in host_facts.POLARS_BELOW_VERSION)
    try:
        parsed = Version(version)
    except InvalidVersion:
        return False
    return SpecifierSet(f">={low},<{high}").contains(parsed, prereleases=True)


def packaging_same_version(first: str, second: str) -> bool:
    if first == second:
        return True
    try:
        return Version(first) == Version(second)
    except InvalidVersion:
        return False


#: The order the text of a specifier set is written in: lower bounds, equalities,
#: exclusions, then upper bounds.
OPERATOR_RANK = {">=": 0, ">": 0, "~=": 0, "==": 1, "===": 1, "!=": 2, "<=": 3, "<": 3}


def packaging_requires(header: str, python: str) -> tuple[str, str]:
    """``(canonical text, in range)`` as ``packaging`` reads a ``Requires-Python``."""
    specifiers = SpecifierSet(header)
    inside = specifiers.contains(Version(python), prereleases=True)
    ordered = sorted(
        specifiers,
        key=lambda spec: (OPERATOR_RANK.get(spec.operator, 4), str(spec)),
    )
    return (",".join(str(spec) for spec in ordered), "yes" if inside else "no")


def python_text(version: tuple[int, int, int, str, int]) -> str:
    major, minor, micro, level, serial = version
    if level == "final":
        return f"{major}.{minor}.{micro}"
    suffix = {"alpha": "a", "beta": "b", "candidate": "rc"}[level]
    return f"{major}.{minor}.{micro}{suffix}{serial}"


@pytest.fixture
def no_packaging(monkeypatch):
    """Every import of ``packaging`` raises ``ModuleNotFoundError`` during the test."""
    names = {"packaging", "packaging.specifiers", "packaging.version", "packaging.tags"}
    names.update(name for name in sys.modules if name.startswith("packaging."))
    for name in sorted(names):
        monkeypatch.setitem(sys.modules, name, None)


@pytest.mark.parametrize(
    ("text", "release"),
    [
        ("1.44.2", (1, 44, 2)),
        ("1.33", (1, 33)),
        ("1.33.0", (1, 33)),
        ("1.33.0.0", (1, 33)),
        ("1.0.0.1", (1, 0, 0, 1)),
        ("3.11", (3, 11)),
        ("3.011", (3, 11)),
        ("01.044.2", (1, 44, 2)),
        ("2.0.0", (2,)),
        ("10", (10,)),
        ("0", ()),
        ("0.0.0", ()),
        ("1" * 64, (int("1" * 64),)),
    ],
)
def test_a_plain_release_is_its_numbers_with_the_trailing_zeros_dropped(text, release):
    assert host_facts._plain_release(text) == release


@pytest.mark.parametrize(
    "text",
    [
        "",
        ".",
        "1.",
        ".1",
        "1..2",
        "1.0rc1",
        "1.0a1",
        "1.0.post1",
        "1.0.dev1",
        "v1.2",
        "1!2",
        "1.2+x",
        "1.2.*",
        " 1.2",
        "1.2 ",
        "1.2\n",
        "1,2",
        "1_2",
        "-1",
        "+1",
        "1e3",
        "\N{FULLWIDTH DIGIT ONE}.\N{FULLWIDTH DIGIT TWO}",
        "\N{ARABIC-INDIC DIGIT ONE}.\N{ARABIC-INDIC DIGIT TWO}",
        "\N{SUPERSCRIPT TWO}",
        "1" * 65,
    ],
)
def test_anything_but_digits_and_dots_is_not_a_plain_release(text):
    assert host_facts._plain_release(text) is None


PLAIN_POLARS_VERSIONS = [
    "1.33",
    "1.33.0",
    "1.33.0.0",
    "1.33.0.1",
    "1.44.2",
    "1.99.4",
    "1.99.99.99",
    "01.044.2",
    "1.044.2",
    "0",
    "0.0.0",
    "1",
    "1.0",
    "1.32.9",
    "1.32.99",
    "2",
    "2.0",
    "2.0.0",
    "2.0.0.0",
    "2.0.0.1",
    "2.0.1",
    "2.1.0",
    "3",
]
OTHER_POLARS_VERSIONS = [
    "1.33.0rc1",
    "1.33.0.dev0",
    "1.33.0.post1",
    "1.33.0+local",
    "1.35.0b1",
    "2.0.0rc1",
    "2.0.0.dev1",
    "2.0.0a1",
    "1!1.44.2",
    "v1.44.2",
    " 1.44.2",
    "1.44.2 ",
    "1.44.2-1",
    "garbage",
    "",
    "1.44.",
    ".1.44",
    "1..44",
    "\N{ARABIC-INDIC DIGIT ONE}.\N{ARABIC-INDIC DIGIT TWO}",
    f"1.{'0' * 70}",
    "1" * 65,
]


@pytest.mark.parametrize("version", PLAIN_POLARS_VERSIONS + OTHER_POLARS_VERSIONS)
def test_the_polars_range_is_what_packaging_says_of_it(version):
    assert host_facts._polars_in_range(version) == packaging_polars_in_range(version)


def test_the_polars_range_follows_the_bounds_the_module_declares(monkeypatch):
    monkeypatch.setattr(host_facts, "POLARS_MIN_VERSION", (1, 40))
    monkeypatch.setattr(host_facts, "POLARS_BELOW_VERSION", (1, 99, 2))
    for version in ("1.39.9", "1.40", "1.40.0", "1.44.2", "1.99.1", "1.99.2", "2.0.0"):
        expected = packaging_polars_in_range(version)
        assert host_facts._polars_in_range(version) == expected, version
    assert host_facts._polars_in_range("1.44.2")
    assert not host_facts._polars_in_range("1.99.2.0")


SAME_VERSION_TEXTS = [
    "1.44.2",
    "1.44.2.0",
    "1.44.02",
    "01.44.2",
    "1.44",
    "1.44.1",
    "v1.44.2",
    " 1.44.2",
    "1.44.2 ",
    "1.44.2rc1",
    "1.44.2.post0",
    "1.44.2+x",
    "1!1.44.2",
    "1.44.2-0",
    "garbage",
    "",
]


def test_two_versions_are_the_same_when_packaging_says_so():
    for first, second in itertools.product(SAME_VERSION_TEXTS, repeat=2):
        expected = packaging_same_version(first, second)
        assert host_facts._same_version(first, second) == expected, (first, second)


def test_a_version_with_a_prefix_is_the_same_as_the_plain_one():
    # Only one side is plain, so the plain fast path must not decide this one.
    assert host_facts._same_version("v1.44.2", "1.44.2")
    assert host_facts._same_version("1.44.2", "v1.44.2")
    assert host_facts._same_version("1.44.2.0", "1.44.2")
    assert not host_facts._same_version("1.44.2.1", "1.44.2")


@pytest.mark.parametrize(
    ("header", "python", "expected"),
    [
        (">=3.11,<3.15", "3.12.15", (">=3.11,<3.15", True)),
        ("<3.15, >=3.11", "3.12.15", (">=3.11,<3.15", True)),
        (" >=3.11 , <3.15 ", "3.15.0", (">=3.11,<3.15", False)),
        (">=3.11,,<3.15,", "3.10.14", (">=3.11,<3.15", False)),
        ("!=3.12.4,>=3.11,<3.15", "3.12.4", (">=3.11,!=3.12.4,<3.15", False)),
        (">=3.011", "3.11.0", (">=3.011", True)),
        ("==3.12", "3.12.0", ("==3.12", True)),
        ("<3.12.15", "3.12.15", ("<3.12.15", False)),
        ("<=3.12.15", "3.12.15", ("<=3.12.15", True)),
        (">3.12.15", "3.12.15", (">3.12.15", False)),
    ],
)
def test_plain_specifiers_read_as_packaging_reads_them(header, python, expected):
    assert host_facts._plain_requires(header, python) == expected
    # The expectations above are packaging's own answers, not a second opinion.
    text, inside = expected
    assert packaging_requires(header, python) == (text, "yes" if inside else "no")


@pytest.mark.parametrize(
    ("header", "python"),
    [
        ("~=3.11", "3.12.15"),
        ("===3.12.15", "3.12.15"),
        ("==3.12.*", "3.12.15"),
        ("!=3.12.*", "3.12.15"),
        (">= 3.11", "3.12.15"),
        (">=3.11rc1", "3.12.15"),
        (">=3.11.post1", "3.12.15"),
        (">=1!3", "3.12.15"),
        (">=v3.11", "3.12.15"),
        # Two pieces that name one bound are one specifier to packaging.
        (">=3.11,>=3.11.0", "3.12.15"),
        (">=3.11,>=3.11", "3.12.15"),
        ("<3.15,<3.15.0", "3.12.15"),
        (">=3.11,>=3.011", "3.12.15"),
        # A piece that is not plain after one that already fails: no early answer.
        ("<3.11,~=3.12", "3.12.15"),
        (">=3.13,< 3.15", "3.12.15"),
        ("", "3.12.15"),
        (" , ", "3.12.15"),
        ("=>3.11", "3.12.15"),
        (">=3.", "3.12.15"),
        ("3.11", "3.12.15"),
        # An interpreter that is not a plain release.
        (">=3.11,<3.15", "3.15.0a1"),
        (">=3.11,<3.15", "3.14.0rc2"),
        (">=3.11,<3.15", ""),
    ],
)
def test_what_is_not_plain_is_left_to_packaging(header, python):
    assert host_facts._plain_requires(header, python) is None


PYTHON_VERSIONS = [
    (3, 12, 15, "final", 0),
    (3, 12, 0, "final", 0),
    (3, 11, 0, "final", 0),
    (3, 10, 14, "final", 0),
    (3, 14, 3, "final", 0),
    (3, 15, 0, "final", 0),
    (3, 15, 0, "alpha", 1),
    (3, 14, 0, "beta", 3),
    (3, 12, 0, "candidate", 1),
]
REQUIRES_HEADERS = [
    ">=3.11,<3.15",
    "<3.15,>=3.11",
    ">=3.11, <3.15",
    " >=3.11 , <3.15 ",
    ">=3.11,<3.15,",
    ",>=3.11,,<3.15",
    ">=3.11.0,<3.15.0",
    ">=3.011",
    ">3.10,<=3.14",
    "<3.15",
    ">=3,<4",
    ">=3.12.15",
    ">3.12.15",
    "<=3.12.15",
    "<3.12.15",
    "==3.12.15",
    "!=3.12.15",
    "==3.12",
    "==3.12.0",
    ">=3.11,<3.15,!=3.12.4",
    "!=3.12.4,<3.15,>=3.11",
    ">=3.11,<=3.14,!=3.13,==3.12.15",
    ">=3.11,>=3.12",
    # Two pieces that name one bound: packaging keeps the first.
    ">=3.11,>=3.11.0",
    ">=3.11.0,>=3.11",
    ">=3.11,>=3.11",
    "<3.15,<3.15.0",
    ">=3.11,>=3.011",
    # Not plain.
    "==3.12.*",
    "!=3.12.*",
    "~=3.11",
    "~=3.12.1",
    "===3.12.15",
    ">= 3.11",
    ">=3.11,< 3.15",
    ">=1!3",
    ">=v3.11",
    ">=3.11rc1,<3.15",
    ">=3.11,<3.15.dev1",
    ">=3.11.post1",
    ">=3.11.0a1",
    # Not plain, after a plain piece that already fails for most of the versions.
    "<3.11,~=3.12",
    "<3.11,==3.12.*",
    ">=3.13,< 3.15",
    # Not a specifier at all.
    "=>3.11",
    ">==3.11",
    "<>3.11",
    "3.11",
    ">=",
    ">=3.",
    ">=3..11",
    ">=3.11+local",
    ">=3.11.*",
    "<3.11.*",
    ">=3.11 and <3.15",
    "\N{GREATER-THAN OR EQUAL TO} 3.11",
    ">=\N{FULLWIDTH DIGIT THREE}.11",
]


@pytest.mark.parametrize("header", REQUIRES_HEADERS)
def test_requires_python_reads_as_packaging_reads_it(tmp_path, header):
    site = polars_site(tmp_path, ash=False)
    seen = site.add_ash(requires_python=header).metadata["Requires-Python"]
    base = linux_host(tmp_path, site=site)
    for version in PYTHON_VERSIONS:
        sources = dataclasses.replace(
            base, python_version=lambda version=version: version
        )
        reading = read(sources)
        try:
            expected = (packaging_requires(seen, python_text(version)), ())
        except Exception as exc:
            expected = ((UNKNOWN, UNKNOWN), (("python_in_range", type(exc).__name__),))
        got = ((reading.requires_python, reading.python_in_range), reading.failed)
        assert got == expected, (header, version)


def test_a_plain_host_reads_in_full_without_importing_packaging(tmp_path, no_packaging):
    reading = read(linux_host(tmp_path))
    assert reading.failed == ()
    assert (reading.polars_runtime, reading.cpu_level) == ("runtime-32", "full")
    assert (reading.python_in_range, reading.requires_python) == ("yes", ">=3.11,<3.15")


def test_the_runtime_of_plain_versions_is_chosen_without_packaging(no_packaging):
    chosen = host_facts.choose_runtime(
        "1.44.2", {"32": "1.44.2.0"}, force=None, prefer=None, injected=False
    )
    assert chosen == ("runtime-32", "32")


@pytest.mark.parametrize(
    ("python", "header"),
    [
        ((3, 15, 0, "alpha", 1), "<3.16,>=3.11"),
        ((3, 12, 15, "final", 0), "~=3.11"),
        ((3, 12, 15, "final", 0), ">=3.11,!=3.12.*"),
        ((3, 12, 15, "final", 0), ">= 3.11"),
        ((3, 12, 15, "final", 0), ">=3.11rc1"),
        ((3, 12, 15, "final", 0), ">=3.11,>=3.11.0"),
    ],
)
def test_a_requires_python_that_is_not_plain_still_goes_to_packaging(
    tmp_path, no_packaging, python, header
):
    # The control of the test above: the same host, with a text the fast path leaves to
    # packaging, reports the import it could not make, so no failure is swallowed.
    site = polars_site(tmp_path, ash=False)
    site.add_ash(requires_python=header)
    sources = dataclasses.replace(
        linux_host(tmp_path, site=site), python_version=lambda: python
    )
    reading = read(sources)
    assert reading.failed == (("python_in_range", "ModuleNotFoundError"),)
    assert (reading.python_in_range, reading.requires_python) == (UNKNOWN, UNKNOWN)


def test_a_polars_that_is_not_plain_still_goes_to_packaging(tmp_path, no_packaging):
    site = polars_site(tmp_path, polars="1.35.0b1")
    reading = read(linux_host(tmp_path, site=site))
    assert reading.failed == (("polars_runtime", "ModuleNotFoundError"),)
    assert (reading.polars_runtime, reading.cpu_level) == (UNKNOWN, UNKNOWN)


def test_a_runtime_version_spelled_with_a_prefix_is_the_same_version(tmp_path):
    site = polars_site(tmp_path, runtimes={})
    site.add_runtime("32", DEFAULT_FLAGS_TEXT, version="v1.44.2")
    reading = read(linux_host(tmp_path, site=site))
    assert (reading.polars_runtime, reading.cpu_level) == ("runtime-32", "full")


def test_a_runtime_version_spelled_with_a_prefix_goes_to_packaging(
    tmp_path, no_packaging
):
    # Only one side is plain: the fast path leaves the comparison to packaging.
    site = polars_site(tmp_path, runtimes={})
    site.add_runtime("32", DEFAULT_FLAGS_TEXT, version="v1.44.2")
    reading = read(linux_host(tmp_path, site=site))
    assert reading.failed == (("polars_runtime", "ModuleNotFoundError"),)


# --------------------------------------------------------------------------------------
# install_channel
# --------------------------------------------------------------------------------------


def channel(
    tmp_path: Path,
    *,
    prefix: str,
    env: Optional[Mapping[str, str]] = None,
    ash: Optional[Mapping[str, object]] = None,
    host: str = "linux",
    realpath: Optional[Callable[[str], str]] = None,
) -> str:
    """The channel one planted host reads, with its prefix, environment and ASH records."""
    site = polars_site(tmp_path, ash=False)
    site.add_ash(**(ash if ash is not None else {}))
    build = {"linux": linux_host, "macos": macos_host, "windows": windows_host}[host]
    sources = build(tmp_path, site=site, prefix=prefix, env=env)
    if realpath is not None:
        sources = dataclasses.replace(sources, realpath=realpath)
    return read(sources, express=True).install_channel


@pytest.mark.parametrize("value", ["YES", "yes", "1", "TRUE", "true", "True"])
def test_the_image_sets_its_own_variable(tmp_path, value):
    assert (
        channel(tmp_path, prefix="/opt/venv", env={"ASH_IN_CONTAINER": value})
        == "image"
    )


@pytest.mark.parametrize("value", ["NO", "no", "0", "false", "", "maybe"])
def test_other_values_of_the_image_variable_do_not_name_the_image(tmp_path, value):
    assert (
        channel(tmp_path, prefix="/opt/venv", env={"ASH_IN_CONTAINER": value})
        != "image"
    )


def test_the_image_wins_over_every_other_channel(tmp_path):
    assert (
        channel(
            tmp_path,
            prefix=LINUX_PREFIX,
            env={"ASH_IN_CONTAINER": "YES"},
            ash={"installer": "pip", "direct_url": '{"dir_info": {"editable": true}}'},
        )
        == "image"
    )


@pytest.mark.parametrize(
    "prefix",
    [
        "/nix/store/0abc123-python3-3.12.8-env",
        "/nix/store/0abc123-ash-3.8.0",
        "/nix/store/0abc123-ash-3.8.0/lib/python3.12/site-packages/..",
    ],
)
def test_a_prefix_in_the_nix_store_is_nix(tmp_path, prefix):
    assert channel(tmp_path, prefix=prefix) == "nix"


def test_a_path_that_only_looks_like_the_nix_store_is_not_nix(tmp_path):
    assert channel(tmp_path, prefix="/home/u/nix/store/venv") != "nix"
    assert channel(tmp_path, prefix="/nix/storeroom/venv") != "nix"


@pytest.mark.parametrize(
    "prefix",
    [
        "/opt/homebrew/Cellar/automated-security-helper/3.8.0/libexec",
        "/usr/local/Cellar/automated-security-helper/3.8.0/libexec",
        "/home/linuxbrew/.linuxbrew/Cellar/automated-security-helper/3.8.0/libexec",
    ],
)
def test_a_prefix_in_a_homebrew_cellar_is_brew(tmp_path, prefix):
    assert channel(tmp_path, prefix=prefix) == "brew"


def test_a_directory_that_is_merely_named_cellar_at_the_end_is_not_brew(tmp_path):
    assert channel(tmp_path, prefix="/srv/Cellar") != "brew"


@pytest.mark.parametrize(
    ("prefix", "env"),
    [
        ("/home/u/.local/share/uv/tools/automated-security-helper", {}),
        (
            "/xdg/data/uv/tools/automated-security-helper",
            {"XDG_DATA_HOME": "/xdg/data"},
        ),
        ("/custom/tools/automated-security-helper", {"UV_TOOL_DIR": "/custom/tools"}),
        # UV_TOOL_DIR wins over XDG_DATA_HOME.
        (
            "/custom/tools/automated-security-helper",
            {"UV_TOOL_DIR": "/custom/tools", "XDG_DATA_HOME": "/xdg/data"},
        ),
    ],
)
def test_a_prefix_under_the_uv_tools_directory_is_uv_tool(tmp_path, prefix, env):
    assert channel(tmp_path, prefix=prefix, env=env) == "uv-tool"


def test_the_default_tools_directory_is_not_used_when_the_variable_moves_it(tmp_path):
    # With UV_TOOL_DIR set, the default directory is no longer where tools live.
    assert (
        channel(
            tmp_path,
            prefix="/home/u/.local/share/uv/tools/automated-security-helper",
            env={"UV_TOOL_DIR": "/custom/tools"},
        )
        != "uv-tool"
    )


@pytest.mark.parametrize(
    ("prefix", "env"),
    [
        ("/home/u/.cache/uv/environments-v2/9f1c2d3e4a5b6c7d", {}),
        (
            "/xdg/cache/uv/environments-v2/9f1c2d3e4a5b6c7d",
            {"XDG_CACHE_HOME": "/xdg/cache"},
        ),
        (
            "/custom/cache/environments-v2/9f1c2d3e4a5b6c7d",
            {"UV_CACHE_DIR": "/custom/cache"},
        ),
    ],
)
def test_a_prefix_in_the_uv_cache_is_uvx(tmp_path, prefix, env):
    assert channel(tmp_path, prefix=prefix, env=env) == "uvx"


@pytest.mark.parametrize(
    ("prefix", "env"),
    [
        ("/home/u/.local/pipx/venvs/automated-security-helper", {}),
        ("/home/u/.local/share/pipx/venvs/automated-security-helper", {}),
        (
            "/opt/pipx-home/venvs/automated-security-helper",
            {"PIPX_HOME": "/opt/pipx-home"},
        ),
    ],
)
def test_a_prefix_under_the_pipx_venvs_directory_is_pipx(tmp_path, prefix, env):
    assert channel(tmp_path, prefix=prefix, env=env) == "pipx"


def test_pipx_home_replaces_the_default_directories(tmp_path):
    assert (
        channel(
            tmp_path,
            prefix="/home/u/.local/pipx/venvs/automated-security-helper",
            env={"PIPX_HOME": "/opt/pipx-home"},
        )
        != "pipx"
    )


@pytest.mark.parametrize(
    "direct_url",
    [
        '{"url": "file:///src/ash", "dir_info": {"editable": true}}',
        '{"dir_info":{"editable":true},"url":"file:///work/ash"}',
    ],
)
def test_an_editable_record_is_a_source_install(tmp_path, direct_url):
    assert (
        channel(tmp_path, prefix="/work/ash/.venv", ash={"direct_url": direct_url})
        == "source"
    )


@pytest.mark.parametrize(
    "direct_url",
    [
        '{"url": "file:///src/ash", "dir_info": {}}',
        '{"url": "file:///src/ash", "dir_info": {"editable": false}}',
        '{"url": "https://example.test/ash.git", "vcs_info": {"vcs": "git"}}',
        '{"url": "https://example.test/ash.whl", "archive_info": {}}',
        "not json",
        "[]",
        '"text"',
        "",
    ],
)
def test_any_other_record_leaves_the_channel_to_the_installer_file(
    tmp_path, direct_url
):
    assert (
        channel(
            tmp_path,
            prefix="/work/ash/.venv",
            ash={"direct_url": direct_url, "installer": "pip"},
        )
        == "pip"
    )


@pytest.mark.parametrize(
    ("installer", "expected"),
    [
        ("pip", "pip"),
        ("PIP", "pip"),
        ("uv", "pip"),
        ("poetry", "unknown"),
        ("conda", "unknown"),
        ("Nix", "unknown"),
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_the_installer_file_names_pip_or_uv_as_pip(tmp_path, installer, expected):
    assert (
        channel(tmp_path, prefix="/work/ash/.venv", ash={"installer": installer})
        == expected
    )


def test_a_prefix_beats_the_records_beside_it(tmp_path):
    # An editable install made inside a pipx venv is a pipx install.
    assert (
        channel(
            tmp_path,
            prefix="/home/u/.local/pipx/venvs/automated-security-helper",
            ash={"direct_url": '{"dir_info": {"editable": true}}'},
        )
        == "pipx"
    )


def test_a_symlinked_home_is_matched_after_resolving_the_links(tmp_path):
    # HOME says /home/u, the interpreter says /local/home/u: only the real paths agree.
    def realpath(path: str) -> str:
        return path.replace("/home/u", "/local/home/u", 1)

    prefix = "/local/home/u/.local/share/uv/tools/automated-security-helper"
    assert channel(tmp_path, prefix=prefix, realpath=realpath) == "uv-tool"
    assert channel(tmp_path / "other", prefix=prefix) != "uv-tool"


def test_a_path_with_dot_dot_is_normalized_before_it_is_compared(tmp_path):
    prefix = "/home/u/.local/share/uv/tools/x/../automated-security-helper"
    assert channel(tmp_path, prefix=prefix) == "uv-tool"
    assert (
        channel(tmp_path / "up", prefix="/home/u/.local/share/uv/../../..") != "uv-tool"
    )


def test_an_empty_prefix_names_no_channel_from_the_prefix(tmp_path):
    assert channel(tmp_path, prefix="", ash={"installer": "poetry"}) == UNKNOWN


def test_windows_tool_and_cache_directories_follow_appdata(tmp_path):
    tools = channel(
        tmp_path / "t",
        prefix="C:\\Users\\u\\AppData\\Roaming\\uv\\data\\tools\\automated-security-helper",
        host="windows",
    )
    cache = channel(
        tmp_path / "c",
        prefix="C:\\Users\\u\\AppData\\Local\\uv\\cache\\environments-v2\\9f1c2d",
        host="windows",
    )
    assert (tools, cache) == ("uv-tool", "uvx")


def test_windows_paths_compare_without_regard_to_case(tmp_path):
    assert (
        channel(
            tmp_path,
            prefix="c:\\users\\U\\appdata\\roaming\\UV\\data\\tools\\automated-security-helper",
            host="windows",
        )
        == "uv-tool"
    )


def test_a_windows_pipx_install_is_found_under_the_home_directory(tmp_path):
    assert (
        channel(
            tmp_path,
            prefix="C:\\Users\\u\\pipx\\venvs\\automated-security-helper",
            host="windows",
        )
        == "pipx"
    )


def test_macos_uses_the_unix_style_defaults(tmp_path):
    assert (
        channel(
            tmp_path,
            prefix="/Users/u/.local/share/uv/tools/automated-security-helper",
            host="macos",
        )
        == "uv-tool"
    )
    assert (
        channel(
            tmp_path / "b",
            prefix="/opt/homebrew/Cellar/automated-security-helper/3.8.0/libexec",
            host="macos",
        )
        == "brew"
    )


def test_a_home_directory_that_cannot_be_found_leaves_only_the_explicit_paths(tmp_path):
    site = polars_site(tmp_path, ash=False)
    site.add_ash(installer="pip")
    sources = dataclasses.replace(
        linux_host(tmp_path, site=site, prefix=LINUX_PREFIX), home=lambda: None
    )
    # No home: the default tools directory cannot be built, so the prefix is no tool dir.
    assert read(sources).install_channel == "pip"
    explicit = dataclasses.replace(
        linux_host(
            tmp_path / "e",
            prefix="/custom/tools/automated-security-helper",
            env={"UV_TOOL_DIR": "/custom/tools"},
        ),
        home=lambda: None,
    )
    assert read(explicit).install_channel == "uv-tool"


# --------------------------------------------------------------------------------------
# express_available
# --------------------------------------------------------------------------------------


def test_express_available_is_the_callers_gate(tmp_path):
    sources = linux_host(tmp_path)
    assert read(sources, express=True).express_available == "yes"
    assert read(sources, express=False).express_available == "no"


def test_without_a_gate_express_available_is_unknown_and_not_a_failure(tmp_path):
    reading = read(linux_host(tmp_path), express=None)
    assert reading.express_available == UNKNOWN
    assert reading.failed == ()


def test_a_gate_that_raises_reads_unknown_and_is_a_failure(tmp_path):
    reading = HostFactsReader(linux_host(tmp_path)).read(express_supported=_raises)
    assert_closed(reading)
    assert reading.express_available == UNKNOWN
    assert ("express_available", "RuntimeError") in reading.failed


# --------------------------------------------------------------------------------------
# A failed reader gives unknown, and unknown raises no notice
# --------------------------------------------------------------------------------------

HOSTS = {"linux": linux_host, "macos": macos_host, "windows": windows_host}
EXPRESS = {"linux": True, "macos": True, "windows": False}

#: Sources whose failure a reader absorbs by reading the same fact another way.
FALLBACK_SOURCES = {"libc_version"}


def recording(sources: Sources) -> tuple[Sources, set[str]]:
    called: set[str] = set()

    def wrap(name: str, function: Callable[..., object]) -> Callable[..., object]:
        def call(*args: object, **kwargs: object) -> object:
            called.add(name)
            return function(*args, **kwargs)

        return call

    wrapped = {
        field.name: wrap(field.name, getattr(sources, field.name))
        for field in dataclasses.fields(Sources)
    }
    return Sources(**wrapped), called


@pytest.mark.parametrize("host", sorted(HOSTS))
def test_the_baseline_decides_every_fact(host, tmp_path):
    reading = read(HOSTS[host](tmp_path), express=EXPRESS[host])
    assert UNKNOWN not in host_facts.fact_tokens(reading).values()


@pytest.mark.parametrize("host", sorted(HOSTS))
def test_a_failing_source_changes_facts_to_unknown_and_nothing_else(host, tmp_path):
    build = HOSTS[host]
    sources = build(tmp_path)
    recorded, called = recording(sources)
    baseline = HostFactsReader(recorded).read(express_supported=lambda: EXPRESS[host])
    assert called, "the baseline reads nothing"
    for source in sorted(called):
        failing = dataclasses.replace(sources, **{source: _raises})
        reading = read(failing, express=EXPRESS[host])
        changed = {
            name
            for name in SUPPORT_FIELDS
            if getattr(reading, name) != getattr(baseline, name)
        }
        assert all(getattr(reading, name) == UNKNOWN for name in changed), (
            source,
            sorted(changed),
        )
        # The facts a failure takes with it are the ones the reader reports as failed
        # or as depending on the failed one: nothing else changes, and nothing that
        # changed is anything but unknown.
        assert {name for name, _kind in reading.failed} <= changed, (
            source,
            reading.failed,
        )
        assert stand_in_matches(reading) == [], source
        if source not in FALLBACK_SOURCES:
            assert changed, f"{source} is read and its failure changes nothing"


@pytest.mark.parametrize(
    ("source", "unknown_facts"),
    [
        (
            "sys_platform",
            {
                "os",
                "host_os",
                "os_release",
                "arch",
                "translation",
                "cpu_level",
                "libc",
                "wsl",
                "install_channel",
            },
        ),
        ("machine", {"arch", "cpu_level"}),
        ("pointer_bits", {"arch", "cpu_level"}),
        ("freedesktop_os_release", {"os_release"}),
        ("python_version", {"python_in_range"}),
        ("implementation_name", {"python_build"}),
        ("gil_disabled", {"python_build"}),
        ("polars_plr_injected", {"polars_runtime", "cpu_level"}),
        ("sys_prefix", {"install_channel"}),
        ("home", {"install_channel"}),
        ("distribution", {"polars_runtime", "cpu_level", "python_in_range"}),
        ("getenv", {"polars_runtime", "cpu_level", "install_channel"}),
        ("libc_version", set()),
    ],
)
def test_the_facts_a_failing_linux_source_takes_with_it(
    tmp_path, source, unknown_facts
):
    sources = linux_host(tmp_path)
    baseline = read(sources)
    reading = read(dataclasses.replace(sources, **{source: _raises}))
    changed = {
        name
        for name in SUPPORT_FIELDS
        if getattr(reading, name) != getattr(baseline, name)
    }
    assert changed == unknown_facts


@pytest.mark.parametrize(
    ("path", "unknown_facts"),
    [("/proc/cpuinfo", {"cpu_level"}), ("/proc/sys/kernel/osrelease", {"wsl"})],
)
def test_an_unreadable_proc_file_takes_only_its_own_fact(tmp_path, path, unknown_facts):
    sources = linux_host(tmp_path)
    inner = sources.read_text

    def read_text(requested: str, limit: int) -> str:
        if requested == path:
            raise OSError(errno.EIO, requested)
        return inner(requested, limit)

    baseline = read(sources)
    reading = read(dataclasses.replace(sources, read_text=read_text))
    changed = {
        name
        for name in SUPPORT_FIELDS
        if getattr(reading, name) != getattr(baseline, name)
    }
    assert changed == unknown_facts
    assert {name for name, _kind in reading.failed} == unknown_facts


def test_every_source_failing_at_once_reads_unknown_everywhere_with_no_notice(tmp_path):
    sources = linux_host(tmp_path)
    everything = dataclasses.replace(
        sources, **{field.name: _raises for field in dataclasses.fields(Sources)}
    )
    reading = HostFactsReader(everything).read(express_supported=_raises)
    assert_closed(reading)
    assert set(host_facts.fact_tokens(reading).values()) == {UNKNOWN}
    assert stand_in_matches(reading) == []
    assert reading.cpu_missing_flags == ()
    assert {name for name, _kind in reading.failed} <= set(SUPPORT_FIELDS)


def test_a_failure_records_the_exception_type_and_never_its_text(tmp_path):
    def leaky() -> str:
        raise RuntimeError("could not read /home/secret/user/file")

    reading = read(dataclasses.replace(linux_host(tmp_path), implementation_name=leaky))
    assert reading.failed == (("python_build", "RuntimeError"),)
    assert "secret" not in repr(reading)


def test_a_planted_unknown_is_the_only_reading_a_failed_fact_has(tmp_path):
    # The same fixture with the failure removed reads the real value (the control).
    sources = linux_host(tmp_path)
    assert read(sources).arch == "amd64"
    assert read(dataclasses.replace(sources, machine=_raises)).arch == UNKNOWN


def test_an_unplanted_read_is_a_test_failure_not_an_unknown(tmp_path):
    sources = dataclasses.replace(
        linux_host(tmp_path), sys_prefix=_unplanted("sys_prefix")
    )
    with pytest.raises(UnplantedRead, match="sys_prefix"):
        HostFactsReader(sources).read(express_supported=lambda: True)


# --------------------------------------------------------------------------------------
# What is read once and what is read every time
# --------------------------------------------------------------------------------------


def counting(sources: Sources) -> tuple[Sources, Counter]:
    counts: Counter = Counter()

    def wrap(name: str, function: Callable[..., object]) -> Callable[..., object]:
        def call(*args: object, **kwargs: object) -> object:
            counts[(name, *args)] += 1
            return function(*args, **kwargs)

        return call

    wrapped = {
        field.name: wrap(field.name, getattr(sources, field.name))
        for field in dataclasses.fields(Sources)
    }
    return Sources(**wrapped), counts


def test_host_facts_that_cannot_change_are_read_once_per_reader(tmp_path):
    sources, counts = counting(linux_host(tmp_path))
    reader = HostFactsReader(sources)
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    assert counts[("read_text", "/proc/cpuinfo", 65536)] == 1
    assert counts[("read_text", "/proc/sys/kernel/osrelease", 4096)] == 1
    assert counts[("libc_version",)] == 1
    assert counts[("freedesktop_os_release",)] == 1
    for name in ("polars", "polars-runtime-32", "automated-security-helper"):
        assert counts[("distribution", name)] == 1, name


def test_what_a_request_can_change_is_read_on_every_call(tmp_path):
    site = polars_site(
        tmp_path, runtimes={"compat": COMPAT_FLAGS_TEXT, "32": DEFAULT_FLAGS_TEXT}
    )
    environment: dict[str, str] = {}
    sources = dataclasses.replace(
        linux_host(tmp_path, site=site), getenv=lambda name: environment.get(name)
    )
    counted, counts = counting(sources)
    reader = HostFactsReader(counted)

    assert reader.read(express_supported=lambda: True).polars_runtime == "compat"
    environment["POLARS_FORCE_PKG"] = "32"
    environment["ASH_IN_CONTAINER"] = "YES"
    forced = reader.read(express_supported=lambda: True)

    assert forced.polars_runtime == "runtime-32"
    assert forced.install_channel == "image"
    assert counts[("getenv", "POLARS_FORCE_PKG")] == 2
    assert counts[("getenv", "ASH_IN_CONTAINER")] == 2
    # The installed distributions were looked up once, for both readings.
    assert counts[("distribution", "polars-runtime-compat")] == 1


def test_the_flags_file_judged_follows_the_runtime_a_request_selects(tmp_path):
    site = polars_site(
        tmp_path, runtimes={"compat": COMPAT_FLAGS_TEXT, "32": DEFAULT_FLAGS_TEXT}
    )
    environment: dict[str, str] = {}
    sources = dataclasses.replace(
        linux_host(tmp_path, site=site), getenv=lambda name: environment.get(name)
    )
    reader = HostFactsReader(sources)
    chosen = reader.read(express_supported=lambda: True)
    environment["POLARS_FORCE_PKG"] = "32"
    forced = reader.read(express_supported=lambda: True)
    # Each runtime is judged against its own file: a file kept from the first reading
    # would not equal the declared set of the second runtime and read as unknown.
    assert (chosen.polars_runtime, chosen.cpu_level) == ("compat", "full")
    assert (forced.polars_runtime, forced.cpu_level) == ("runtime-32", "full")


def test_a_failed_read_is_remembered_not_retried(tmp_path):
    attempts = []

    def failing_once(path: str, limit: int) -> str:
        attempts.append(path)
        raise OSError(errno.EIO, path)

    reader = HostFactsReader(
        dataclasses.replace(linux_host(tmp_path), read_text=failing_once)
    )
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    assert ("cpu_level", "OSError") in second.failed
    assert sorted(attempts) == ["/proc/cpuinfo", "/proc/sys/kernel/osrelease"]


class Counted:
    """A real distribution behind a proxy that counts what the reader asks of it.

    ``fail`` names the attributes whose read raises ``RuntimeError`` instead.
    """

    def __init__(self, inner: PathDistribution, fail: Collection[str] = ()) -> None:
        self._inner = inner
        self._fail = frozenset(fail)
        self.asked: Counter = Counter()

    def __getattr__(self, name: str) -> Any:
        self.asked[name] += 1
        if name in self._fail:
            raise RuntimeError(f"planted failure reading {name}")
        return getattr(self._inner, name)


def counted_distributions(
    site: Site, fail: Optional[Mapping[str, Collection[str]]] = None
) -> tuple[Callable[[str], Optional[Counted]], dict[str, Counted]]:
    """A ``distribution`` source over ``site`` whose answers count what is asked of them."""
    proxies: dict[str, Counted] = {}

    def lookup(name: str) -> Optional[Counted]:
        found = site.lookup(name)
        if found is None:
            return None
        key = canonical(name)
        if key not in proxies:
            proxies[key] = Counted(found, (fail or {}).get(key, ()))
        return proxies[key]

    return lookup, proxies


def counted_sources(
    tmp_path: Path, site: Site, fail: Optional[Mapping[str, Collection[str]]] = None
) -> tuple[Sources, dict[str, Counted]]:
    lookup, proxies = counted_distributions(site, fail)
    sources = dataclasses.replace(linux_host(tmp_path, site=site), distribution=lookup)
    return sources, proxies


def test_installed_distributions_are_read_once_per_reader(tmp_path):
    site = polars_site(
        tmp_path,
        runtimes={
            "compat": COMPAT_FLAGS_TEXT,
            "64": DEFAULT_FLAGS_TEXT,
            "32": DEFAULT_FLAGS_TEXT,
        },
    )
    sources, proxies = counted_sources(tmp_path, site)
    reader = HostFactsReader(sources)
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    assert first.polars_runtime == "compat"
    for name in (
        "polars",
        "polars-runtime-compat",
        "polars-runtime-64",
        "polars-runtime-32",
    ):
        assert proxies[name].asked["version"] == 1, name
    # The flags file of the runtime in use is found once, and ASH's metadata is parsed
    # once, not once per reading.
    assert proxies["polars-runtime-compat"].asked["files"] == 1
    assert proxies["automated-security-helper"].asked["metadata"] == 1


def test_a_new_reader_reads_the_distributions_again(tmp_path):
    sources, proxies = counted_sources(tmp_path, polars_site(tmp_path))
    HostFactsReader(sources).read(express_supported=lambda: True)
    HostFactsReader(sources).read(express_supported=lambda: True)
    assert proxies["polars"].asked["version"] == 2
    assert proxies["automated-security-helper"].asked["metadata"] == 2


def test_a_failed_version_read_is_remembered_not_retried(tmp_path):
    sources, proxies = counted_sources(
        tmp_path, polars_site(tmp_path), fail={"polars": {"version"}}
    )
    reader = HostFactsReader(sources)
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    assert ("polars_runtime", "RuntimeError") in second.failed
    assert (second.polars_runtime, second.cpu_level) == (UNKNOWN, UNKNOWN)
    assert proxies["polars"].asked["version"] == 1


def test_a_failed_requires_python_read_is_remembered_not_retried(tmp_path):
    site = polars_site(tmp_path, ash=False)
    site.add_ash(requires_python="not a specifier")
    sources, proxies = counted_sources(tmp_path, site)
    reader = HostFactsReader(sources)
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    assert ("python_in_range", "InvalidSpecifier") in second.failed
    assert proxies["automated-security-helper"].asked["metadata"] == 1


def test_the_default_reader_is_built_once_per_process(tmp_path, monkeypatch):
    built = []

    def factory() -> Sources:
        built.append(1)
        return linux_host(tmp_path)

    monkeypatch.setattr(host_facts, "_PROCESS_READER", None)
    monkeypatch.setattr(host_facts, "Sources", factory)
    first = host_facts.read_host_facts(express_supported=lambda: True)
    second = host_facts.read_host_facts(express_supported=lambda: True)
    assert first == second
    assert first.os == "linux"
    assert len(built) == 1


def test_a_reading_from_given_sources_does_not_touch_the_process_reader(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(host_facts, "_PROCESS_READER", None)
    host_facts.read_host_facts(linux_host(tmp_path), express_supported=lambda: True)
    assert host_facts._PROCESS_READER is None


# --------------------------------------------------------------------------------------
# The two small readers other modules call
# --------------------------------------------------------------------------------------


def test_read_os_release_is_the_recorded_release_text(tmp_path):
    assert host_facts.read_os_release(linux_host(tmp_path)) == "ubuntu 24.04"
    assert host_facts.read_os_release(macos_host(tmp_path / "m")) == "macos 15.1"
    assert (
        host_facts.read_os_release(windows_host(tmp_path / "w")) == "windows 10.0.26100"
    )


def test_read_libc_is_the_libc_token(tmp_path):
    assert host_facts.read_libc(linux_host(tmp_path)) == "glibc"
    assert host_facts.read_libc(macos_host(tmp_path / "m")) == "n/a"


def test_the_two_readers_return_unknown_on_any_failure_and_never_raise(tmp_path):
    sources = dataclasses.replace(
        linux_host(tmp_path),
        freedesktop_os_release=_raises,
        libc_version=_raises,
        platform_tags=_raises,
    )
    assert host_facts.read_os_release(sources) == UNKNOWN
    assert host_facts.read_libc(sources) == UNKNOWN
    broken = dataclasses.replace(linux_host(tmp_path / "b"), sys_platform=_raises)
    assert host_facts.read_os_release(broken) == UNKNOWN
    assert host_facts.read_libc(broken) == UNKNOWN


def test_each_reader_asks_only_for_what_it_needs(tmp_path):
    # Nothing but sys_platform and the one source is planted: any other read raises.
    only_release = planted(
        sys_platform=lambda: "linux",
        freedesktop_os_release=lambda: {"ID": "debian", "VERSION_ID": "12"},
    )
    assert host_facts.read_os_release(only_release) == "debian 12"
    only_libc = planted(sys_platform=lambda: "linux", libc_version=lambda: "glibc 2.36")
    assert host_facts.read_libc(only_libc) == "glibc"


# --------------------------------------------------------------------------------------
# The module itself
# --------------------------------------------------------------------------------------

#: What the module may import when it is imported. Everything else is imported inside
#: the function that needs it, so that importing the module costs nearly nothing and a
#: platform pays only for the readers its own facts use.
MODULE_SCOPE_IMPORTS = {
    "__future__",
    "dataclasses",
    "os",
    "posixpath",
    "sys",
    "typing",
}


def _module_tree() -> ast.Module:
    return ast.parse(Path(host_facts.__file__).read_text(encoding="utf-8"))


def _module_scope_imports(tree: ast.Module) -> set[str]:
    names: set[str] = set()

    def visit(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.If):
                test = node.test
                guarded = (
                    isinstance(test, ast.Name) and test.id == "TYPE_CHECKING"
                ) or (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")
                if not guarded:
                    visit(node.body)
                visit(node.orelse)
            elif isinstance(node, (ast.Try, ast.With)):
                visit(node.body)

    visit(tree.body)
    return names


def test_importing_the_module_loads_only_the_cheap_standard_library():
    assert _module_scope_imports(_module_tree()) <= MODULE_SCOPE_IMPORTS


def test_the_module_imports_nothing_from_the_rest_of_ash():
    imported: set[str] = set()
    for node in ast.walk(_module_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "a relative import reaches into the package"
            imported.add(node.module or "")
    assert not {
        name for name in imported if name.split(".")[0] == "automated_security_helper"
    }
    assert not {name for name in imported if name.split(".")[0] == "polars"}


def test_the_control_the_import_walk_sees_a_planted_module_scope_import():
    planted_tree = ast.parse("import subprocess\nfrom importlib import metadata\n")
    assert _module_scope_imports(planted_tree) == {"subprocess", "importlib"}
    guarded = ast.parse(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import collections\n"
    )
    assert _module_scope_imports(guarded) == {"typing"}


def test_a_module_scope_ntpath_import_is_one_the_walk_would_flag():
    # ntpath is imported inside the one reader that needs it, on Windows only.
    planted_tree = ast.parse("import ntpath\n")
    assert not _module_scope_imports(planted_tree) <= MODULE_SCOPE_IMPORTS


def test_the_sources_are_exactly_the_host_reads_the_module_makes():
    live = Sources()
    assert all(
        callable(getattr(live, field.name)) for field in dataclasses.fields(Sources)
    )
    assert {field.name for field in dataclasses.fields(Sources)} == {
        "sys_platform",
        "machine",
        "sysconfig_platform",
        "pointer_bits",
        "read_text",
        "freedesktop_os_release",
        "mac_version",
        "windows_version",
        "sysctl_int",
        "sysctl_str",
        "wow64_machines",
        "windows_feature_present",
        "libc_version",
        "platform_tags",
        "distribution",
        "getenv",
        "sys_prefix",
        "realpath",
        "home",
        "python_version",
        "implementation_name",
        "gil_disabled",
        "polars_plr_injected",
    }


# --------------------------------------------------------------------------------------
# The live readers, on planted files and a planted import path
# --------------------------------------------------------------------------------------


def test_the_live_text_read_is_bounded_and_replaces_bad_bytes(tmp_path):
    target = tmp_path / "file"
    target.write_bytes(b"abc\xffdef-and-more")
    assert host_facts._live_read_text(str(target), 7) == "abc\ufffddef"
    assert host_facts._live_read_text(str(target), 4096) == "abc\ufffddef-and-more"
    with pytest.raises(FileNotFoundError):
        host_facts._live_read_text(str(tmp_path / "absent"), 10)


def test_the_live_distribution_lookup_answers_none_for_a_missing_name(
    tmp_path, monkeypatch
):
    site = Site(tmp_path)
    site.add("zz-planted-dist", "2.1")
    monkeypatch.syspath_prepend(str(site.root))
    found = host_facts._live_distribution("zz-planted-dist")
    assert found is not None and found.version == "2.1"
    assert host_facts._live_distribution("zz-no-such-dist-anywhere") is None
