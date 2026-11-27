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
import ntpath
import os
import struct
import subprocess
import sys
import warnings
from collections import Counter
from importlib.metadata import PathDistribution
from pathlib import Path
from typing import Any, Callable, Collection, Mapping, Optional

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


def planted_elf(
    interpreter: Optional[str], *, bits: int = 64, order: str = "little"
) -> bytes:
    """The first bytes of an ELF executable whose program loader is ``interpreter``.

    The bytes are an ELF header, two program headers (a loadable segment, then the
    interpreter segment) and the loader's name, in the width and byte order asked for.
    ``interpreter`` None gives the second header a note segment instead, which is what
    a statically linked executable has: no loader to name.
    """
    endian = "<" if order == "little" else ">"

    def pack(layout: str, *values: int) -> bytes:
        return struct.pack(endian + layout, *values)

    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2 if bits == 64 else 1])
    ident += bytes([1 if order == "little" else 2, 1]) + bytes(9)
    entry = 56 if bits == 64 else 32
    table = 64 if bits == 64 else 52
    end = table + 2 * entry
    name = b"" if interpreter is None else interpreter.encode("ascii") + b"\x00"
    length = len(name)
    top = end + length
    kind = 4 if interpreter is None else 3
    if bits == 64:
        header = pack("HHIQQQIHHHHHH", 2, 62, 1, 0, table, 0, 0, 64, entry, 2, 0, 0, 0)
        load = pack("IIQQQQQQ", 1, 5, 0, 0, 0, top, top, 4096)
        second = pack("IIQQQQQQ", kind, 4, end, end, end, length, length, 1)
    else:
        header = pack("HHIIIIIHHHHHH", 2, 3, 1, 0, table, 0, 0, 52, entry, 2, 0, 0, 0)
        load = pack("IIIIIIII", 1, 0, 0, 0, top, top, 5, 4096)
        second = pack("IIIIIIII", kind, end, end, end, length, length, 4, 1)
    return ident + header + load + second + name


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

#: Every fact a host reader fills, in the order a reading holds them.
READING_FIELDS = [
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

#: The fields a support row matches on, in their order: the reading's facts without
#: ``os_release``, which the design records beside them and no row matches on.
SUPPORT_FIELDS = [name for name in READING_FIELDS if name != "os_release"]


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

    def read_head(path: str, limit: int) -> bytes:
        return planted_elf("/lib64/ld-linux-x86-64.so.2")[:limit]

    return planted(
        sys_platform=lambda: "linux",
        machine=lambda: "x86_64",
        pointer_bits=lambda: 64,
        read_text=read_text,
        freedesktop_os_release=lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"},
        libc_version=lambda: "glibc 2.39",
        # The interpreter's executable names the glibc loader, so a C library read that
        # fails is still answered (the fallback is read from this file, never run).
        executable=lambda: "/usr/bin/python3",
        read_head=read_head,
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
    assert reading.os_release == "ubuntu 24.04"
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
    assert reading.os_release == "macos 15.1"
    assert reading.failed == ()
    assert stand_in_matches(reading) == []


def test_the_supported_windows_host_reads_as_a_native_x64_machine(tmp_path):
    reading = read(windows_host(tmp_path), express=False)
    assert host_facts.fact_tokens(reading) == {
        "os": "windows",
        "host_os": "windows",
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
    assert reading.os_release == "windows 10.0.26100"
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


def test_os_release_is_recorded_and_no_support_row_matches_on_it():
    # The design records the release text beside the facts and matches nothing on it:
    # it is a field of the reading, not one of the fields a row matches on, and it has
    # no closed vocabulary.
    assert "os_release" not in FACT_FIELDS
    assert "os_release" not in host_facts.TOKENS
    assert "os_release" in {field.name for field in dataclasses.fields(HostReading)}


def test_the_reading_carries_exactly_those_fields_and_its_details():
    names = [field.name for field in dataclasses.fields(HostReading)]
    assert names[: len(READING_FIELDS)] == READING_FIELDS
    assert names[len(READING_FIELDS) :] == [
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
    assert "os_release" not in mapping


def test_failures_are_listed_in_the_order_of_the_reading_fields(tmp_path):
    # os_release leaves the fields a row matches on, not the failures a reading names.
    sources = dataclasses.replace(
        linux_host(tmp_path), freedesktop_os_release=_raises, machine=_raises
    )
    names = [name for name, _kind in read(sources).failed]
    assert "os_release" in names
    assert names == sorted(names, key=READING_FIELDS.index)


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
    ("platform_name", "wow64", "expected"),
    [
        ("win-amd64", (0, IMAGE_FILE_MACHINE_AMD64), "native"),
        # arm64 Python on Windows on Arm: native.
        ("win-arm64", (0, IMAGE_FILE_MACHINE_ARM64), "native"),
        # x64 Python on Windows on Arm runs under emulation with no WOW64 layer, so the
        # call names no process machine beside the arm64 native machine: the
        # interpreter's own architecture says which of the two this is.
        ("win-amd64", (0, IMAGE_FILE_MACHINE_ARM64), "x64-on-arm64"),
        # An interpreter that is neither family cannot be placed beside (0, arm64).
        ("win32", (0, IMAGE_FILE_MACHINE_ARM64), "unknown"),
        ("", (0, IMAGE_FILE_MACHINE_ARM64), "unknown"),
        # A process machine of its own beside an arm64 host is emulation too.
        (
            "win-amd64",
            (IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64),
            "x64-on-arm64",
        ),
        ("win-amd64", (0x1234, 0x5678), "unknown"),
        # Windows before 10 1511 has no IsWow64Process2.
        ("win-amd64", AttributeError("IsWow64Process2"), "unknown"),
        ("win-amd64", OSError(errno.EINVAL, "failed"), "unknown"),
    ],
)
def test_windows_translation_follows_iswow64process2_and_the_interpreter(
    tmp_path, platform_name, wow64, expected
):
    reading = read(windows_host(tmp_path, platform_name=platform_name, wow64=wow64))
    assert reading.translation == expected


@pytest.mark.parametrize(
    ("native_machine", "expected"),
    [
        # 32-bit x86 on 64-bit x86 Windows is WOW64, which translates nothing.
        (IMAGE_FILE_MACHINE_AMD64, "native"),
        # 32-bit x86 emulated on arm64 has no token: unknown, never x64-on-arm64.
        (IMAGE_FILE_MACHINE_ARM64, "unknown"),
    ],
)
def test_a_32_bit_python_on_windows_is_a_wow64_process(
    tmp_path, native_machine, expected
):
    # Only a 32-bit interpreter reports an x86 process machine, so the host is planted
    # with the platform name and the pointer size such an interpreter has.
    sources = dataclasses.replace(
        windows_host(
            tmp_path,
            platform_name="win32",
            wow64=(IMAGE_FILE_MACHINE_I386, native_machine),
        ),
        pointer_bits=lambda: 32,
    )
    reading = read(sources)
    assert (reading.arch, reading.translation) == ("other", expected)


def test_an_x64_python_on_a_windows_arm_host_matches_the_emulation_row(tmp_path):
    reading = read(
        windows_host(
            tmp_path, platform_name="win-amd64", wow64=(0, IMAGE_FILE_MACHINE_ARM64)
        )
    )
    assert (reading.arch, reading.translation) == ("amd64", "x64-on-arm64")
    assert stand_in_matches(reading) == ["host.translation.x64-on-arm64"]


def test_an_arm64_python_on_a_windows_arm_host_is_native_and_matches_no_row(tmp_path):
    reading = read(
        windows_host(
            tmp_path, platform_name="win-arm64", wow64=(0, IMAGE_FILE_MACHINE_ARM64)
        )
    )
    assert (reading.arch, reading.translation) == ("arm64", "native")
    assert stand_in_matches(reading) == []


def test_an_unreadable_interpreter_architecture_leaves_arm_host_translation_unknown(
    tmp_path,
):
    sources = dataclasses.replace(
        windows_host(tmp_path, wow64=(0, IMAGE_FILE_MACHINE_ARM64)),
        sysconfig_platform=_raises,
    )
    reading = read(sources)
    assert reading.translation == UNKNOWN
    assert ("translation", "RuntimeError") in reading.failed
    assert stand_in_matches(reading) == []


def test_linux_translation_is_native_beside_an_x86_processor(tmp_path):
    # sysctl_int and wow64_machines stay unplanted on the Linux host.
    assert read(linux_host(tmp_path)).translation == "native"


def only_the_kernel_release(sources: Sources) -> Sources:
    """The host with every read of ``/proc/cpuinfo`` left unplanted."""
    inner = sources.read_text

    def read_text(path: str, limit: int) -> str:
        if path == "/proc/sys/kernel/osrelease":
            return inner(path, limit)
        raise UnplantedRead(path)

    return dataclasses.replace(sources, read_text=read_text)


@pytest.mark.parametrize("machine", ["aarch64", "arm64", "i686", "ppc64le"])
def test_linux_translation_off_x86_64_is_native_and_reads_no_cpuinfo(tmp_path, machine):
    # The processor file is unplanted: a read of it raises UnplantedRead.
    sources = dataclasses.replace(
        only_the_kernel_release(linux_host(tmp_path)), machine=lambda: machine
    )
    assert read(sources).translation == "native"


def test_linux_translation_of_a_machine_with_no_name_is_unknown(tmp_path):
    # An x86-64 reading cannot be checked against a processor of an unnamed machine.
    reading = read(dataclasses.replace(linux_host(tmp_path), machine=lambda: ""))
    assert (reading.arch, reading.translation) == (UNKNOWN, UNKNOWN)
    assert reading.failed == ()


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
        # The first WSL2 kernels carry no WSL2 suffix; microsoft-standard names them.
        ("4.19.128-microsoft-standard\n", "wsl2"),
        ("4.19.104-microsoft-standard", "wsl2"),
        ("4.19.121-Microsoft-Standard", "wsl2"),
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


def test_glibc_is_answered_by_the_c_library_and_reads_no_executable(tmp_path):
    sources = dataclasses.replace(
        linux_host(tmp_path),
        executable=_unplanted("executable"),
        read_head=_unplanted("read_head"),
    )
    assert read(sources).libc == "glibc"


def test_libc_is_not_applicable_off_linux(tmp_path):
    # libc_version, executable and read_head stay unplanted there.
    assert read(macos_host(tmp_path)).libc == "n/a"
    assert read(windows_host(tmp_path / "w")).libc == "n/a"


# The C library read says glibc or it says nothing. When it says nothing the answer is
# the loader the interpreter's own executable names, read as a file: the module starts
# no child process, so the libc fallback may not run a loader (what packaging does to
# find a musl version) and may not call anything that does.


@pytest.fixture
def child_processes(monkeypatch):
    """The child processes a test starts, each one recorded and refused.

    Nothing runs: ``subprocess.Popen`` (so ``run``, ``check_output`` and ``os.popen``),
    ``os.system`` and ``os.posix_spawn`` note the call and raise instead.
    """
    started: list[str] = []

    class Refusing(subprocess.Popen):  # type: ignore[type-arg]
        def __init__(self, *args: object, **kwargs: object) -> None:
            started.append("subprocess.Popen")
            raise RuntimeError("a child process was started")

    def refuse(name: str) -> Callable[..., object]:
        def start(*args: object, **kwargs: object) -> object:
            started.append(name)
            raise RuntimeError("a child process was started")

        return start

    monkeypatch.setattr(subprocess, "Popen", Refusing)
    monkeypatch.setattr(os, "system", refuse("os.system"))
    monkeypatch.setattr(os, "posix_spawn", refuse("os.posix_spawn"), raising=False)
    return started


def test_the_child_process_detector_records_a_planted_start(child_processes):
    with pytest.raises(RuntimeError):
        subprocess.run(["/bin/true"], check=False)
    with pytest.raises(RuntimeError):
        os.system("/bin/true")
    assert child_processes == ["subprocess.Popen", "os.system"]


def libc_beside(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: Optional[bytes],
    *,
    libc_version: Callable[[], str] = _raises,
) -> str:
    """What ``libc()`` says on a Linux host whose C library read does not answer.

    The interpreter is found the way a run finds it, through ``sys.executable``, and
    its executable is a file holding ``content`` (None: a file that is not there).
    Only the platform and the C library read come from the test: ``libc()`` reads no
    other fact. A failed read gives ``failed <exception type>``.
    """
    executable = tmp_path / "python3"
    if content is not None:
        executable.write_bytes(content)
    monkeypatch.setattr(sys, "executable", str(executable))
    sources = dataclasses.replace(
        Sources(), sys_platform=lambda: "linux", libc_version=libc_version
    )
    try:
        return HostFactsReader(sources).libc()
    except host_facts._SourceFailure as failure:
        return f"failed {failure.failure.kind}"
    except Exception as exc:
        return f"failed {type(exc).__name__}"


def test_a_musl_host_is_read_without_starting_a_child_process(
    tmp_path, monkeypatch, child_processes
):
    content = planted_elf("/lib/ld-musl-x86_64.so.1")
    got = libc_beside(tmp_path, monkeypatch, content)
    assert child_processes == [], "the libc read started a child process"
    assert got == "musl"


def test_a_glibc_loader_is_read_without_starting_a_child_process(
    tmp_path, monkeypatch, child_processes
):
    content = planted_elf("/lib64/ld-linux-x86-64.so.2")
    got = libc_beside(tmp_path, monkeypatch, content)
    assert child_processes == []
    assert got == "glibc"


#: (id, loader, planted_elf options, libc): what the loader an executable names says.
LOADERS = [
    ("musl-x86_64", "/lib/ld-musl-x86_64.so.1", {}, "musl"),
    ("musl-aarch64", "/lib/ld-musl-aarch64.so.1", {}, "musl"),
    ("musl-armhf", "/lib/ld-musl-armhf.so.1", {"bits": 32}, "musl"),
    ("musl-mips", "/lib/ld-musl-mips.so.1", {"bits": 32, "order": "big"}, "musl"),
    ("musl-s390x", "/lib/ld-musl-s390x.so.1", {"order": "big"}, "musl"),
    ("glibc-x86_64", "/lib64/ld-linux-x86-64.so.2", {}, "glibc"),
    ("glibc-aarch64", "/lib/ld-linux-aarch64.so.1", {}, "glibc"),
    ("glibc-armhf", "/lib/ld-linux-armhf.so.3", {"bits": 32}, "glibc"),
    ("glibc-ppc64le", "/lib64/ld64.so.2", {}, "glibc"),
    ("glibc-s390x", "/lib/ld64.so.1", {"order": "big"}, "glibc"),
    # A loader of neither family names no library this reader knows.
    ("bionic", "/system/bin/linker64", {}, "unknown"),
    ("uclibc", "/lib/ld-uClibc.so.0", {}, "unknown"),
    # A statically linked executable has no loader at all.
    ("static", None, {}, "unknown"),
]


@pytest.mark.parametrize(
    ("interpreter", "options", "expected"),
    [pytest.param(*case[1:], id=case[0]) for case in LOADERS],
)
def test_a_silent_c_library_leaves_the_answer_to_the_loader_the_executable_names(
    tmp_path, monkeypatch, child_processes, interpreter, options, expected
):
    content = planted_elf(interpreter, **options)
    assert libc_beside(tmp_path, monkeypatch, content) == expected
    assert child_processes == []


_WHOLE_ELF = planted_elf("/lib/ld-musl-x86_64.so.1")

#: (id, content): files that are not an ELF executable, or not all of one.
NOT_ELF = [
    ("a-script", b'#!/bin/sh\nexec python3.12 "$@"\n'),
    ("empty", b""),
    ("the-magic-alone", b"\x7fELF"),
    ("header-cut-short", _WHOLE_ELF[:30]),
    ("program-headers-cut-short", _WHOLE_ELF[:100]),
    ("loader-name-cut-short", _WHOLE_ELF[:-8]),
    ("an-unknown-class", b"\x7fELF\x03\x01\x01" + bytes(120)),
    ("an-unknown-byte-order", b"\x7fELF\x02\x03\x01" + bytes(120)),
]


@pytest.mark.parametrize(
    "content", [pytest.param(case[1], id=case[0]) for case in NOT_ELF]
)
def test_an_executable_that_is_not_a_whole_elf_file_names_no_library(
    tmp_path, monkeypatch, child_processes, content
):
    assert libc_beside(tmp_path, monkeypatch, content) == UNKNOWN
    assert child_processes == []


def test_an_executable_that_is_not_there_is_a_failed_libc_read(
    tmp_path, monkeypatch, child_processes
):
    got = libc_beside(tmp_path, monkeypatch, None)
    assert got == "failed FileNotFoundError"
    assert child_processes == []


def test_an_interpreter_with_no_executable_path_names_no_library(
    monkeypatch, child_processes
):
    monkeypatch.setattr(sys, "executable", "")
    sources = dataclasses.replace(
        Sources(), sys_platform=lambda: "linux", libc_version=_raises
    )
    assert HostFactsReader(sources).libc() == UNKNOWN
    assert child_processes == []


@pytest.mark.parametrize(
    ("version", "loader", "expected"),
    [
        # A C library that is not glibc, or gives no text, leaves it to the loader.
        ("uClibc 1.0", "/lib/ld-musl-x86_64.so.1", "musl"),
        ("", "/lib64/ld-linux-x86-64.so.2", "glibc"),
    ],
)
def test_a_c_library_that_does_not_say_glibc_leaves_the_answer_to_the_loader(
    tmp_path, monkeypatch, child_processes, version, loader, expected
):
    content = planted_elf(loader)
    got = libc_beside(tmp_path, monkeypatch, content, libc_version=lambda: version)
    assert got == expected
    assert child_processes == []


# The same fallback through planted sources: what the reader asks of the host, and how
# it reads the program header table of a head that is cut, lying or oversized.


def a_silent_c_library() -> str:
    raise ValueError("unrecognized configuration name")


def with_executable(
    sources: Sources,
    head: bytes,
    *,
    asked: Optional[list[tuple[str, int]]] = None,
    libc_version: Callable[[], str] = a_silent_c_library,
) -> Sources:
    """``sources`` with a silent C library and an executable that starts with ``head``.

    ``asked`` collects each ``(path, limit)`` the executable is read with.
    """

    def read_head(path: str, limit: int) -> bytes:
        if asked is not None:
            asked.append((path, limit))
        return head[:limit]

    return dataclasses.replace(
        sources,
        libc_version=libc_version,
        executable=lambda: "/opt/python/bin/python3",
        read_head=read_head,
    )


def elf_with_loader_at(index: int, interpreter: str) -> bytes:
    """A 64-bit little-endian ELF head whose loader is the program header ``index``.

    The headers before it are null entries: only the length of the table differs from
    ``planted_elf``.
    """
    entry, table = 56, 64
    name = interpreter.encode("ascii") + b"\x00"
    end = table + (index + 1) * entry
    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1]) + bytes(9)
    header = struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0, table, 0, 0, 64, entry, index + 1, 0, 0, 0
    )
    null = struct.pack("<IIQQQQQQ", 0, 0, 0, 0, 0, 0, 0, 1)
    loader = struct.pack("<IIQQQQQQ", 3, 4, end, end, end, len(name), len(name), 1)
    return ident + header + null * index + loader + name


def patched(content: bytes, start: int, value: int, size: int) -> bytes:
    """``content`` with the little-endian number at ``start`` replaced by ``value``."""
    return content[:start] + value.to_bytes(size, "little") + content[start + size :]


#: (id, head, libc): a 64-bit head whose header table is bounded or does not add up.
ELF_SHAPES = [
    # The first 64 program headers are read, and the loader comes before the rest.
    (
        "loader-at-the-last-header-read",
        elf_with_loader_at(63, "/lib/ld-musl-x86_64.so.1"),
        "musl",
    ),
    (
        "loader-past-the-last-header-read",
        elf_with_loader_at(64, "/lib/ld-musl-x86_64.so.1"),
        "unknown",
    ),
    # A table that claims more headers than the head holds stops at the loader.
    ("more-headers-than-the-head-holds", patched(_WHOLE_ELF, 0x38, 0xFFFF, 2), "musl"),
    ("no-program-headers", patched(_WHOLE_ELF, 0x38, 0, 2), "unknown"),
    ("an-entry-size-below-the-minimum", patched(_WHOLE_ELF, 0x36, 8, 2), "unknown"),
    ("a-table-beyond-the-head", patched(_WHOLE_ELF, 0x20, 1 << 40, 8), "unknown"),
    ("a-loader-name-with-no-end", _WHOLE_ELF[:-1] + b"x", "unknown"),
    # The loader's segment has to lie inside the head, though its name ends inside it.
    ("a-segment-longer-than-the-head", patched(_WHOLE_ELF, 152, 1 << 20, 8), "unknown"),
]


@pytest.mark.parametrize(
    ("interpreter", "options", "expected"),
    [pytest.param(*case[1:], id=case[0]) for case in LOADERS],
)
def test_the_loader_a_planted_executable_names_decides_a_silent_c_library(
    tmp_path, interpreter, options, expected
):
    head = planted_elf(interpreter, **options)
    assert read(with_executable(linux_host(tmp_path), head)).libc == expected


@pytest.mark.parametrize(
    "content", [pytest.param(case[1], id=case[0]) for case in NOT_ELF]
)
def test_a_planted_executable_that_is_not_a_whole_elf_file_reads_unknown(
    tmp_path, content
):
    reading = read(with_executable(linux_host(tmp_path), content))
    assert reading.libc == UNKNOWN
    assert reading.failed == ()


@pytest.mark.parametrize(
    ("content", "expected"),
    [pytest.param(*case[1:], id=case[0]) for case in ELF_SHAPES],
)
def test_the_program_header_table_is_read_within_its_bounds(
    tmp_path, content, expected
):
    assert read(with_executable(linux_host(tmp_path), content)).libc == expected


def test_the_loader_name_is_the_string_the_interp_header_points_at():
    assert host_facts._elf_interpreter(_WHOLE_ELF) == "/lib/ld-musl-x86_64.so.1"
    big_32 = planted_elf("/lib/ld.so.1", bits=32, order="big")
    assert host_facts._elf_interpreter(big_32) == "/lib/ld.so.1"
    assert host_facts._elf_interpreter(planted_elf(None)) is None


def test_the_executable_is_read_for_a_bounded_head_once_per_reader(tmp_path):
    asked: list[tuple[str, int]] = []
    head = planted_elf("/lib/ld-musl-x86_64.so.1")
    reader = HostFactsReader(with_executable(linux_host(tmp_path), head, asked=asked))
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first.libc == second.libc == "musl"
    assert asked == [("/opt/python/bin/python3", 4096)]


# A loader's name can lie past the first read. The standalone Pythons that uv installs
# hold it about 115 KB into the file, long after the program headers that point at it,
# so one more read reaches it, up to a limit.

PLANTED_PATH = "/opt/python/bin/python3"
MUSL_LOADER = "/lib/ld-musl-x86_64.so.1"
GLIBC_LOADER = "/lib64/ld-linux-x86-64.so.2"


def elf_with_loader_far_in(offset: int, interpreter: str) -> bytes:
    """A 64-bit little-endian ELF whose loader's name starts at file ``offset``.

    The one program header is the loader's, in the table at the start of the file as in
    every executable; the bytes between the table and the name are zeros, and the file
    ends with the name.
    """
    entry, table = 56, 64
    name = interpreter.encode("ascii") + b"\x00"
    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2, 1, 1]) + bytes(9)
    header = struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0, table, 0, 0, 64, entry, 1, 0, 0, 0
    )
    loader = struct.pack(
        "<IIQQQQQQ", 3, 4, offset, offset, offset, len(name), len(name), 1
    )
    start = ident + header + loader
    return start + bytes(offset - len(start)) + name


#: (id, loader, libc): the two families of loader, each named far into the file.
FAR_LOADERS = [
    ("musl", MUSL_LOADER, "musl"),
    ("glibc", GLIBC_LOADER, "glibc"),
]

#: (id, where the name starts for a name of ``size`` bytes): names that the first read
#: of 4096 bytes does not hold whole. The last one ends exactly at the limit of the
#: second read, 1 MiB.
FAR_PLACES = [
    ("straddling-the-first-read", lambda size: 4096 - 5),
    ("just-past-the-first-read", lambda size: 4096),
    ("where-a-standalone-build-has-it", lambda size: 114_800),
    ("ending-at-the-limit", lambda size: (1 << 20) - size),
]

#: (id, head): a loader whose name ends past the limit of the second read. Both heads
#: are as long as the first read, so that a short file is not what stops a second one.
BEYOND_THE_LIMIT = [
    (
        "ending-one-byte-past-the-limit",
        elf_with_loader_far_in((1 << 20) - len(MUSL_LOADER), MUSL_LOADER),
    ),
    (
        "starting-in-a-far-off-corner",
        patched(_WHOLE_ELF, 128, 1 << 40, 8) + bytes(4096),
    ),
]


@pytest.mark.parametrize(
    ("interpreter", "expected"),
    [pytest.param(*case[1:], id=case[0]) for case in FAR_LOADERS],
)
@pytest.mark.parametrize(
    "place", [pytest.param(case[1], id=case[0]) for case in FAR_PLACES]
)
def test_a_loader_name_past_the_first_read_is_reached_with_one_more_read(
    tmp_path, place, interpreter, expected
):
    size = len(interpreter) + 1
    offset = place(size)
    asked: list[tuple[str, int]] = []
    head = elf_with_loader_far_in(offset, interpreter)
    reading = read(with_executable(linux_host(tmp_path), head, asked=asked))
    assert reading.libc == expected
    assert reading.failed == ()
    assert asked == [(PLANTED_PATH, 4096), (PLANTED_PATH, offset + size)]


@pytest.mark.parametrize(
    "head", [pytest.param(case[1], id=case[0]) for case in BEYOND_THE_LIMIT]
)
def test_a_loader_name_that_ends_past_the_limit_is_not_looked_for(tmp_path, head):
    asked: list[tuple[str, int]] = []
    reading = read(with_executable(linux_host(tmp_path), head, asked=asked))
    assert reading.libc == UNKNOWN
    assert reading.failed == ()
    assert asked == [(PLANTED_PATH, 4096)]


def test_a_loader_name_past_the_end_of_the_file_reads_unknown(tmp_path):
    size = len(MUSL_LOADER) + 1
    whole = elf_with_loader_far_in(114_800, MUSL_LOADER)
    asked: list[tuple[str, int]] = []
    reading = read(with_executable(linux_host(tmp_path), whole[:5000], asked=asked))
    assert reading.libc == UNKNOWN
    assert reading.failed == ()
    assert asked == [(PLANTED_PATH, 4096), (PLANTED_PATH, 114_800 + size)]


def test_a_file_that_the_first_read_holds_whole_is_not_read_again(tmp_path):
    # The file is 201 bytes, shorter than the first read, and its header puts the name
    # 114,800 bytes in: a read of more bytes could not find any.
    asked: list[tuple[str, int]] = []
    short = patched(_WHOLE_ELF, 128, 114_800, 8)
    reading = read(with_executable(linux_host(tmp_path), short, asked=asked))
    assert reading.libc == UNKNOWN
    assert reading.failed == ()
    assert asked == [(PLANTED_PATH, 4096)]


def test_a_loader_name_far_in_is_read_twice_in_all_by_a_reader(tmp_path):
    asked: list[tuple[str, int]] = []
    head = elf_with_loader_far_in(114_800, MUSL_LOADER)
    reader = HostFactsReader(with_executable(linux_host(tmp_path), head, asked=asked))
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first.libc == second.libc == "musl"
    assert asked == [
        (PLANTED_PATH, 4096),
        (PLANTED_PATH, 114_800 + len(MUSL_LOADER) + 1),
    ]


def test_a_failing_second_read_reads_unknown_and_is_a_failure(tmp_path):
    head = elf_with_loader_far_in(114_800, MUSL_LOADER)

    def read_head(path: str, limit: int) -> bytes:
        if limit > 4096:
            raise RuntimeError("planted failure")
        return head[:limit]

    sources = dataclasses.replace(
        with_executable(linux_host(tmp_path), head), read_head=read_head
    )
    reading = read(sources)
    assert reading.libc == UNKNOWN
    assert ("libc", "RuntimeError") in reading.failed


@pytest.mark.parametrize(
    ("interpreter", "expected"),
    [pytest.param(*case[1:], id=case[0]) for case in FAR_LOADERS],
)
def test_a_loader_name_far_into_a_file_is_read_with_no_child_process(
    tmp_path, monkeypatch, child_processes, interpreter, expected
):
    content = elf_with_loader_far_in(114_800, interpreter)
    assert libc_beside(tmp_path, monkeypatch, content) == expected
    assert child_processes == []


def test_the_loader_segment_is_where_the_interp_header_puts_it():
    size = len(MUSL_LOADER) + 1
    far = elf_with_loader_far_in(114_800, MUSL_LOADER)
    assert host_facts._elf_loader_segment(_WHOLE_ELF) == (176, size)
    # The headers are inside the first read, the name they point at is not.
    assert host_facts._elf_loader_segment(far[:4096]) == (114_800, size)
    assert host_facts._elf_interpreter(far[:4096]) is None
    assert host_facts._elf_interpreter(far) == MUSL_LOADER
    assert host_facts._elf_loader_segment(planted_elf(None)) is None
    assert host_facts._elf_loader_segment(b"") is None


@pytest.mark.parametrize("source", ["executable", "read_head"])
def test_a_failing_executable_source_reads_unknown_and_is_a_failure(tmp_path, source):
    sources = with_executable(linux_host(tmp_path), planted_elf(None))
    reading = read(dataclasses.replace(sources, **{source: _raises}))
    assert reading.libc == UNKNOWN
    assert ("libc", "RuntimeError") in reading.failed


def test_an_empty_executable_path_reads_unknown_and_reads_no_file(tmp_path):
    sources = dataclasses.replace(
        with_executable(linux_host(tmp_path), planted_elf(None)),
        executable=lambda: "",
        read_head=_unplanted("read_head"),
    )
    reading = read(sources)
    assert reading.libc == UNKNOWN
    assert reading.failed == ()


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
# What a first reading asks of the installed distributions
# --------------------------------------------------------------------------------------


def test_the_versions_and_the_requires_python_are_read_from_their_header_lines(
    tmp_path,
):
    # The version is the Version: line of the METADATA text and ASH's Requires-Python
    # its own line, so a distribution whose parsed metadata is unreadable still reads.
    unparsed = {"version", "metadata"}
    sources, proxies = counted_sources(
        tmp_path,
        polars_site(tmp_path),
        fail={
            "polars": unparsed,
            "polars-runtime-32": unparsed,
            "automated-security-helper": unparsed,
        },
    )
    reading = read(sources)
    assert reading.failed == ()
    assert (reading.polars_runtime, reading.cpu_level) == ("runtime-32", "full")
    assert (reading.python_in_range, reading.requires_python) == ("yes", ">=3.11,<3.15")
    assert proxies["polars"].reads["METADATA"] == 1


RUNTIME_TEXTS = {
    "compat": COMPAT_FLAGS_TEXT,
    "64": DEFAULT_FLAGS_TEXT,
    "32": DEFAULT_FLAGS_TEXT,
}


@pytest.mark.parametrize(
    ("installed", "env", "runtime", "looked_up"),
    [
        # Only the 32-bit runtime: polars tries the other two first, and so does the
        # reader, because only the lookup tells that a runtime is absent.
        (["32"], {}, "runtime-32", ["compat", "64", "32"]),
        # The first runtime polars tries that loads decides, so the rest are never
        # looked up.
        (["compat", "64", "32"], {}, "compat", ["compat"]),
        (["64", "32"], {}, "runtime-64", ["compat", "64"]),
        # A forced runtime is the only one tried; a preferred one is tried first.
        (["compat", "64", "32"], {"POLARS_FORCE_PKG": "64"}, "runtime-64", ["64"]),
        (["32"], {"POLARS_PREFER_PKG": "32"}, "runtime-32", ["32"]),
        (["compat", "32"], {"POLARS_PREFER_PKG": "32"}, "runtime-32", ["32"]),
        # A forced runtime that is not installed is absent, whatever else is.
        (["compat", "32"], {"POLARS_FORCE_PKG": "64"}, "absent", ["64"]),
        # A variable that names no runtime leaves every runtime unlooked.
        (["32"], {"POLARS_FORCE_PKG": "nope"}, UNKNOWN, []),
    ],
)
def test_the_runtimes_looked_up_are_those_polars_would_try_in_its_order(
    tmp_path, installed, env, runtime, looked_up
):
    texts = {selector: RUNTIME_TEXTS[selector] for selector in installed}
    site = polars_site(tmp_path, runtimes=texts)
    reading = read(linux_host(tmp_path, site=site, env=env))
    assert reading.polars_runtime == runtime
    assert site.lookups == [
        "polars",
        *(f"polars-runtime-{selector}" for selector in looked_up),
        "automated-security-helper",
    ]


#: (id, METADATA text): every shape of header block a reader of the Version: line has
#: to agree with importlib.metadata about, the parsed answer being the one that stands.
METADATA_SHAPES = [
    ("plain", "Metadata-Version: 2.1\nName: x\nVersion: 1.44.2\nSummary: s\n\nbody\n"),
    ("no-blank-line", "Name: x\nVersion: 1.44.2\n"),
    ("only-the-version", "Version: 1.44.2\n"),
    ("no-space-after-the-colon", "Version:1.44.2\n"),
    ("a-tab-after-the-colon", "Version:\t1.44.2\n"),
    ("trailing-spaces", "Version:   1.44.2   \nName: x\n"),
    ("windows-line-ends", "Version: 1.44.2\r\nName: x\r\n"),
    ("old-mac-line-ends", "Version: 1.44.2\rName: x\r"),
    ("a-continuation-line", "Version: 1.44.2\n continued\nName: x\n"),
    ("a-folded-value", "Version:\n 1.44.2\nName: x\n"),
    ("an-indented-line-before", "Name: x\n version: 3\nVersion: 1.44.2\n"),
    ("a-lower-case-name", "version: 1.44.2\n"),
    ("an-upper-case-name", "VERSION: 1.44.2\n"),
    ("a-repeated-header", "Version: 1.44.2\nVersion: 2.0\n"),
    ("after-the-blank-line", "Name: x\n\nVersion: 1.44.2\n"),
    ("a-blank-first-line", "\nVersion: 1.44.2\n"),
    ("a-line-that-is-no-header", "Name: x\nnot a header\nVersion: 1.44.2\n"),
    ("an-empty-value", "Version: \n"),
    ("no-version", "Name: x\n"),
    ("an-empty-file", ""),
    ("a-byte-order-mark", "\N{BYTE ORDER MARK}Version: 1.44.2\n"),
    ("a-line-separator-in-the-value", "Version: 1.44.2\N{LINE SEPARATOR}x\nName: y\n"),
    ("a-v-prefix", "Version: v1.44.2\n"),
    ("a-local-version", "Version: 1.44.2+local\n"),
    ("non-ascii-digits", "Version: \N{ARABIC-INDIC DIGIT ONE}.2\n"),
    ("a-space-before-the-colon", "Version : 1.44.2\n"),
]


@pytest.mark.parametrize(
    "text", [pytest.param(text, id=name) for name, text in METADATA_SHAPES]
)
def test_the_version_agrees_with_importlib_metadata_on_every_shape(tmp_path, text):
    info = tmp_path / "x-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_bytes(text.encode("utf-8"))
    distribution = PathDistribution(info)
    try:
        expected: Any = distribution.version
    except Exception as exc:
        expected = ("raises", type(exc).__name__)
    try:
        got: Any = HostFactsReader(NOTHING)._version("x", distribution)
    except host_facts._SourceFailure as failure:
        got = ("raises", failure.failure.kind)
    assert got == expected


class ParserOnly:
    """A distribution whose METADATA text reads as missing for ``read_text``.

    A reader that looks for a header line in that text finds none and asks the metadata
    parser, which reads the file itself: the answer the header-line read must equal.
    """

    def __init__(self, inner: PathDistribution) -> None:
        self._inner = inner

    def read_text(self, filename: str) -> Optional[str]:
        return None if filename == "METADATA" else self._inner.read_text(filename)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


#: (id, METADATA text): the shapes of a header block that carries ASH's Requires-Python.
REQUIRES_SHAPES = [
    ("plain", "Name: x\nVersion: 3.8.0\nRequires-Python: <3.15,>=3.11\n\nbody\n"),
    ("a-single-bound", "Requires-Python: >=3.11\n"),
    ("outside-the-range", "Requires-Python: >=3.13\n"),
    ("spaces-around-the-pieces", "Requires-Python: >=3.11 , <3.15\n"),
    ("trailing-spaces", "Requires-Python: >=3.11,<3.15   \n"),
    ("a-compatible-release", "Requires-Python: ~=3.11\n"),
    ("not-a-specifier", "Requires-Python: not a specifier\n"),
    ("no-header", "Name: x\nVersion: 3.8.0\n"),
    ("an-empty-value", "Requires-Python: \n"),
    ("blanks-only", "Requires-Python:   \t \n"),
    ("a-folded-value", "Requires-Python:\n >=3.11,<3.15\n"),
    ("a-continued-value", "Requires-Python: >=3.11,\n <3.15\n"),
    ("a-lower-case-name", "requires-python: >=3.11\n"),
    ("a-repeated-header", "Requires-Python: >=3.11\nRequires-Python: <3.0\n"),
    ("after-the-blank-line", "Name: x\n\nRequires-Python: <3.0\n"),
    ("windows-line-ends", "Requires-Python: >=3.11\r\nName: x\r\n"),
    ("a-line-that-is-no-header", "Name: x\nnot a header\nRequires-Python: <3.0\n"),
    ("a-space-before-the-colon", "Requires-Python : >=3.11\n"),
    ("a-byte-order-mark", "\N{BYTE ORDER MARK}Requires-Python: >=3.11\n"),
    ("an-empty-file", ""),
]


def requires_python_of(distribution: Any) -> Any:
    """What the reader makes of ASH's Requires-Python from ``distribution``, or how it fails."""
    sources = planted(distribution=lambda name: distribution)
    try:
        return ("reads", HostFactsReader(sources)._requires_python("3.12.15"))
    except host_facts._SourceFailure as failure:
        return ("raises", failure.failure.kind)


@pytest.mark.parametrize(
    "text", [pytest.param(text, id=name) for name, text in REQUIRES_SHAPES]
)
def test_the_requires_python_agrees_with_the_metadata_parser_on_every_shape(
    tmp_path, text
):
    info = tmp_path / "x-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_bytes(text.encode("utf-8"))
    distribution = PathDistribution(info)
    assert requires_python_of(distribution) == requires_python_of(
        ParserOnly(distribution)
    )


def test_the_requires_python_shapes_are_not_all_one_answer(tmp_path):
    # The control for the table above: its shapes read both ways and fail, so an
    # agreement between two readers that always said the same thing would show here.
    outcomes = set()
    for index, (_name, text) in enumerate(REQUIRES_SHAPES):
        info = tmp_path / f"x{index}-1.0.dist-info"
        info.mkdir()
        (info / "METADATA").write_bytes(text.encode("utf-8"))
        outcomes.add(repr(requires_python_of(PathDistribution(info))))
    assert any("'yes'" in outcome for outcome in outcomes)
    assert any("'no'" in outcome for outcome in outcomes)
    assert any("raises" in outcome for outcome in outcomes)
    assert any("unknown" in outcome for outcome in outcomes)


def test_a_metadata_text_with_no_requires_python_warns_of_nothing(tmp_path):
    # A header block the parser has to read (it holds a line that is no header) and that
    # has no Requires-Python. From Python 3.12 the parser's mapping warns of an implicit
    # None when a missing key is subscripted, and a run that turns warnings into errors
    # would fail the read: the reader asks whether the key is there first.
    distribution = Site(tmp_path).add(
        "automated-security-helper", "3.8.0", headers="not a header\n"
    )
    # The control: this text is one the reader leaves to the parser.
    text = distribution.read_text("METADATA")
    assert host_facts._plain_header(text, "Requires-Python") == (False, None)
    assert "Requires-Python" not in distribution.metadata
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert requires_python_of(distribution) == ("reads", (UNKNOWN, UNKNOWN))


@pytest.mark.parametrize(
    ("text", "name", "expected"),
    [
        ("Name: x\nVersion: 1.2\n", "Version", (True, "1.2")),
        # Only the blanks after the colon are dropped, and the name's case is free.
        ("Name: x\nversion:  1.2 \t\n", "VERSION", (True, "1.2 \t")),
        ("Version:1.2", "Version", (True, "1.2")),
        ("Name: x\n", "Version", (True, None)),
        ("Name: x\n\nVersion: 1.2\n", "Version", (True, None)),
        ("A: 1\n b\nVersion: 1.2\n\nbody", "Version", (True, "1.2")),
        # Anything else is for the parser to read.
        (None, "Version", (False, None)),
        ("", "Version", (False, None)),
        ("\n\nVersion: 1.2\n", "Version", (False, None)),
        ("\nVersion: 1.2\n", "Version", (False, None)),
        (" Version: 1.2\n", "Version", (False, None)),
        ("Version: 1.2\r\n", "Version", (False, None)),
        ("Version: 1.2\n more\n", "Version", (False, None)),
        ("Version:\n 1.2\n", "Version", (False, None)),
        ("Name: x\nnot a header\n", "Version", (False, None)),
        ("Name x\nVersion: 1.2\n", "Version", (False, None)),
        (": 1.2\nVersion: 1.2\n", "Version", (False, None)),
        ("Version : 1.2\n", "Version", (False, None)),
        ("Vers\N{LATIN SMALL LETTER E WITH ACUTE}on: 1.2\n", "Version", (False, None)),
    ],
)
def test_a_plain_header_block_gives_the_first_header_and_any_other_text_the_parser(
    text, name, expected
):
    assert host_facts._plain_header(text, name) == expected


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
    # The prefix names no channel and the installer file says uv: pip.
    assert (
        channel(tmp_path, prefix="/opt/venv", env={"ASH_IN_CONTAINER": value}) == "pip"
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
    assert channel(tmp_path, prefix="/home/u/nix/store/venv") == "pip"
    assert channel(tmp_path, prefix="/nix/storeroom/venv") == "pip"


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
    assert channel(tmp_path, prefix="/srv/Cellar") == "pip"


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
        == "pip"
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
        # uvx runs from the archive its environment is kept in: ``<cache>/archive-v0/<id>``
        # (the layout ``python_installer.is_uvx_environment`` looks for), where ``<id>``
        # is the 21 characters uv names an archive by.
        ("/home/u/.cache/uv/archive-v0/rZ0pJnA3yqDy7sd4mvNm1", {}),
        (
            "/xdg/cache/uv/archive-v0/rZ0pJnA3yqDy7sd4mvNm1",
            {"XDG_CACHE_HOME": "/xdg/cache"},
        ),
        (
            "/custom/cache/archive-v0/rZ0pJnA3yqDy7sd4mvNm1",
            {"UV_CACHE_DIR": "/custom/cache"},
        ),
        # The directory's version is not part of the rule, here or for the environments.
        ("/home/u/.cache/uv/archive-v1/rZ0pJnA3yqDy7sd4mvNm1", {}),
    ],
)
def test_a_prefix_in_the_uv_cache_is_uvx(tmp_path, prefix, env):
    assert channel(tmp_path, prefix=prefix, env=env) == "uvx"


@pytest.mark.parametrize(
    "prefix",
    [
        # The cache's own directories hold no environment of their own.
        "/home/u/.cache/uv",
        "/home/u/.cache/uv/archive-v0",
        "/home/u/.cache/uv/environments-v2",
        # Nor do the other buckets of the cache.
        "/home/u/.cache/uv/wheels-v5/pypi/ash/3.8.0",
        "/home/u/.cache/uv/builds-v0/archive-v0/rZ0pJnA3yqDy7sd4mvNm1",
        # A directory that only begins with the name of the cache is not under it.
        "/home/u/.cache/uv-old/archive-v0/rZ0pJnA3yqDy7sd4mvNm1",
        # A name that is no versioned bucket.
        "/home/u/.cache/uv/archive/rZ0pJnA3yqDy7sd4mvNm1",
        "/home/u/.cache/uv/my-archive-v0/rZ0pJnA3yqDy7sd4mvNm1",
    ],
)
def test_a_path_in_the_uv_cache_that_holds_no_environment_is_not_uvx(tmp_path, prefix):
    assert channel(tmp_path, prefix=prefix) == "pip"


@pytest.mark.parametrize(
    ("prefix", "env"),
    [
        ("/home/u/.local/pipx/venvs/automated-security-helper", {}),
        ("/home/u/.local/share/pipx/venvs/automated-security-helper", {}),
        (
            "/opt/pipx-home/venvs/automated-security-helper",
            {"PIPX_HOME": "/opt/pipx-home"},
        ),
        # Where XDG_DATA_HOME is set, pipx's home is under it ...
        (
            "/xdg/data/pipx/venvs/automated-security-helper",
            {"XDG_DATA_HOME": "/xdg/data"},
        ),
        # ... and the default homes stay pipx's: an environment made before the
        # variable was set is still where it was made.
        (
            "/home/u/.local/share/pipx/venvs/automated-security-helper",
            {"XDG_DATA_HOME": "/xdg/data"},
        ),
    ],
)
def test_a_prefix_under_the_pipx_venvs_directory_is_pipx(tmp_path, prefix, env):
    assert channel(tmp_path, prefix=prefix, env=env) == "pipx"


@pytest.mark.parametrize(
    ("host", "prefix"),
    [
        # platformdirs, which pipx takes its home from, ignores XDG_DATA_HOME on macOS
        # and Windows.
        ("macos", "/xdg/data/pipx/venvs/automated-security-helper"),
        ("windows", "C:\\xdg\\data\\pipx\\venvs\\automated-security-helper"),
    ],
)
def test_xdg_data_home_is_no_pipx_home_off_linux(tmp_path, host, prefix):
    env = {"XDG_DATA_HOME": "C:\\xdg\\data" if host == "windows" else "/xdg/data"}
    assert channel(tmp_path, prefix=prefix, env=env, host=host) == "pip"


@pytest.mark.parametrize(
    ("host", "prefix", "env", "expected"),
    [
        # Windows: pipx's user data directory is %LOCALAPPDATA%\pipx\pipx, and its older
        # homes are under the user's profile.
        (
            "windows",
            "C:\\Users\\u\\AppData\\Local\\pipx\\pipx\\venvs\\automated-security-helper",
            {},
            "pipx",
        ),
        (
            "windows",
            "C:\\Users\\u\\.local\\pipx\\venvs\\automated-security-helper",
            {},
            "pipx",
        ),
        (
            "windows",
            "c:\\users\\U\\appdata\\local\\PIPX\\pipx\\venvs\\automated-security-helper",
            {},
            "pipx",
        ),
        # The variables that move a home are read, not assumed.
        (
            "windows",
            "E:\\Local\\pipx\\pipx\\venvs\\automated-security-helper",
            {"LOCALAPPDATA": "E:\\Local"},
            "pipx",
        ),
        (
            "windows",
            "C:\\Users\\u\\AppData\\Local\\pipx\\pipx\\venvs\\automated-security-helper",
            {"LOCALAPPDATA": "E:\\Local"},
            "pip",
        ),
        (
            "windows",
            "D:\\tools\\pipx\\venvs\\automated-security-helper",
            {"PIPX_HOME": "D:\\tools\\pipx"},
            "pipx",
        ),
        (
            "windows",
            "C:\\Users\\u\\pipx\\venvs\\automated-security-helper",
            {"PIPX_HOME": "D:\\tools\\pipx"},
            "pip",
        ),
        # macOS: platformdirs' user data directory, and the two Unix homes.
        (
            "macos",
            "/Users/u/Library/Application Support/pipx/venvs/automated-security-helper",
            {},
            "pipx",
        ),
        (
            "macos",
            "/Users/u/.local/pipx/venvs/automated-security-helper",
            {},
            "pipx",
        ),
        (
            "macos",
            "/Users/u/.local/share/pipx/venvs/automated-security-helper",
            {},
            "pipx",
        ),
        (
            "macos",
            "/opt/pipx-home/venvs/automated-security-helper",
            {"PIPX_HOME": "/opt/pipx-home"},
            "pipx",
        ),
        (
            "macos",
            "/Users/u/Library/Application Support/pipx/venvs/automated-security-helper",
            {"PIPX_HOME": "/opt/pipx-home"},
            "pip",
        ),
        # Library/Application Support is macOS's own: on Linux it is no pipx home.
        (
            "linux",
            "/home/u/Library/Application Support/pipx/venvs/automated-security-helper",
            {},
            "pip",
        ),
    ],
)
def test_pipx_homes_follow_each_platforms_defaults(
    tmp_path, host, prefix, env, expected
):
    assert channel(tmp_path, prefix=prefix, env=env, host=host) == expected


def test_pipx_home_replaces_the_default_directories(tmp_path):
    assert (
        channel(
            tmp_path,
            prefix="/home/u/.local/pipx/venvs/automated-security-helper",
            env={"PIPX_HOME": "/opt/pipx-home"},
        )
        == "pip"
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
    # HOME says /home/u, the interpreter says /data/home/u: only the real paths agree.
    # The resolver is idempotent, as a real one is: a path that is already resolved
    # comes back as it is, so the reader may resolve a path more than once.
    realpath = link_resolver("/home", "/data/home")
    assert realpath(realpath("/home/u")) == realpath("/home/u") == "/data/home/u"
    prefix = "/data/home/u/.local/share/uv/tools/automated-security-helper"
    assert channel(tmp_path, prefix=prefix, realpath=realpath) == "uv-tool"
    assert channel(tmp_path / "other", prefix=prefix) == "pip"


def link_resolver(link: str, target: str) -> Callable[[str], str]:
    """A ``realpath`` that follows one link: the paths under it move, no others."""

    def realpath(path: str) -> str:
        if path == link or path.startswith(link + "/"):
            return target + path[len(link) :]
        return path

    return realpath


def junction_resolver(link: str, target: str) -> Callable[[str], str]:
    """The same for a Windows junction, matched without regard to case."""

    def realpath(path: str) -> str:
        shown = ntpath.normcase(path)
        base = ntpath.normcase(link)
        if shown == base or shown.startswith(base + "\\"):
            return target + path[len(link) :]
        return path

    return realpath


@pytest.mark.parametrize(
    ("link", "target", "prefix", "env", "expected"),
    [
        # HOME is /home/u and /home is a link to /data/home. A tool environment is
        # created at the spelling the tool directory has, and the interpreter keeps
        # that spelling in sys.prefix, so the prefix is the link's spelling too.
        (
            "/home",
            "/data/home",
            "/home/u/.local/share/uv/tools/automated-security-helper",
            {},
            "uv-tool",
        ),
        (
            "/home",
            "/data/home",
            "/home/u/.cache/uv/environments-v2/9f1c2d3e4a5b6c7d",
            {},
            "uvx",
        ),
        (
            "/home",
            "/data/home",
            "/home/u/.cache/uv/archive-v0/rZ0pJnA3yqDy7sd4mvNm1",
            {},
            "uvx",
        ),
        (
            "/home",
            "/data/home",
            "/home/u/.local/pipx/venvs/automated-security-helper",
            {},
            "pipx",
        ),
        (
            "/home",
            "/data/home",
            "/home/u/.local/share/pipx/venvs/automated-security-helper",
            {},
            "pipx",
        ),
        # The directory a variable names is spelled through the link as well, or by
        # its real path while the prefix keeps the link's spelling.
        (
            "/home",
            "/data/home",
            "/home/u/tools/automated-security-helper",
            {"UV_TOOL_DIR": "/home/u/tools"},
            "uv-tool",
        ),
        (
            "/home",
            "/data/home",
            "/home/u/tools/automated-security-helper",
            {"UV_TOOL_DIR": "/data/home/u/tools"},
            "uv-tool",
        ),
        # The tools directory itself is the link.
        (
            "/home/u/.local/share/uv/tools",
            "/mnt/big/uv-tools",
            "/home/u/.local/share/uv/tools/automated-security-helper",
            {},
            "uv-tool",
        ),
    ],
)
def test_a_prefix_spelled_through_a_link_is_matched_after_resolving_it(
    tmp_path, link, target, prefix, env, expected
):
    realpath = link_resolver(link, target)
    assert channel(tmp_path, prefix=prefix, env=env, realpath=realpath) == expected


def test_a_prefix_beside_the_link_but_not_under_this_home_is_no_tool_of_it(tmp_path):
    realpath = link_resolver("/home", "/data/home")
    prefix = "/home/other/.local/share/uv/tools/automated-security-helper"
    assert channel(tmp_path, prefix=prefix, realpath=realpath) == "pip"


@pytest.mark.parametrize("linked", [False, True])
def test_a_sibling_directory_that_starts_with_the_tools_directorys_name_is_no_tool(
    tmp_path, linked
):
    # tools-old begins with the text of the tools directory without being under it.
    realpath = link_resolver("/home", "/data/home") if linked else None
    prefix = "/home/u/.local/share/uv/tools-old/automated-security-helper"
    assert channel(tmp_path, prefix=prefix, realpath=realpath) == "pip"


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        (WINDOWS_PREFIX, "uv-tool"),
        ("C:\\Users\\u\\AppData\\Local\\uv\\cache\\environments-v2\\9f1c2d", "uvx"),
        (
            "C:\\Users\\u\\AppData\\Local\\uv\\cache\\archive-v0\\rZ0pJnA3yqDy7sd4mvNm1",
            "uvx",
        ),
        ("C:\\Users\\u\\pipx\\venvs\\automated-security-helper", "pipx"),
    ],
)
def test_a_windows_prefix_spelled_through_a_junction_is_matched_after_resolving_it(
    tmp_path, prefix, expected
):
    realpath = junction_resolver("C:\\Users\\u", "D:\\Users\\u")
    got = channel(tmp_path, prefix=prefix, host="windows", realpath=realpath)
    assert got == expected


def test_a_path_with_dot_dot_is_normalized_before_it_is_compared(tmp_path):
    prefix = "/home/u/.local/share/uv/tools/x/../automated-security-helper"
    assert channel(tmp_path, prefix=prefix) == "uv-tool"
    assert channel(tmp_path / "up", prefix="/home/u/.local/share/uv/../../..") == "pip"


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
    archive = channel(
        tmp_path / "a",
        prefix="C:\\Users\\u\\AppData\\Local\\uv\\cache\\archive-v0\\rZ0pJnA3yqDy7sd4mvNm1",
        host="windows",
    )
    assert (tools, cache, archive) == ("uv-tool", "uvx", "uvx")


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
            for name in READING_FIELDS
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


#: Everything that depends on the name of the operating system.
LOST_WITH_THE_PLATFORM = {
    "os",
    "host_os",
    "os_release",
    "arch",
    "translation",
    "cpu_level",
    "libc",
    "wsl",
    "install_channel",
}

#: For each baseline host, the facts that go to ``unknown`` when one source fails, and
#: no others. Each set is spelled out, so a fact that comes to depend on one more source
#: (or on one fewer) changes a row here instead of passing as "some facts went unknown".
#: ``read_text`` is read for two files and has its own table below.
FAILURE_TABLES: dict[str, dict[str, set[str]]] = {
    "linux": {
        "sys_platform": LOST_WITH_THE_PLATFORM,
        # The machine is named for the architecture and the processor level, and beside
        # an x86-64 machine the translation is checked against the processor file.
        "machine": {"arch", "cpu_level", "translation"},
        "pointer_bits": {"arch", "cpu_level", "translation"},
        "freedesktop_os_release": {"os_release"},
        "python_version": {"python_in_range"},
        "implementation_name": {"python_build"},
        "gil_disabled": {"python_build"},
        "polars_plr_injected": {"polars_runtime", "cpu_level"},
        "sys_prefix": {"install_channel"},
        "realpath": {"install_channel"},
        "home": {"install_channel"},
        "distribution": {"polars_runtime", "cpu_level", "python_in_range"},
        "getenv": {"polars_runtime", "cpu_level", "install_channel"},
        # The C library read has a fallback: the interpreter's own loader answers.
        "libc_version": set(),
    },
    "macos": {
        "sys_platform": LOST_WITH_THE_PLATFORM,
        "machine": {"arch", "cpu_level"},
        "pointer_bits": {"arch", "cpu_level"},
        "mac_version": {"os_release"},
        "sysctl_int": {"translation"},
        "sysctl_str": {"cpu_level"},
        "python_version": {"python_in_range"},
        "implementation_name": {"python_build"},
        "gil_disabled": {"python_build"},
        "polars_plr_injected": {"polars_runtime", "cpu_level"},
        "sys_prefix": {"install_channel"},
        "realpath": {"install_channel"},
        "home": {"install_channel"},
        "distribution": {"polars_runtime", "cpu_level", "python_in_range"},
        "getenv": {"polars_runtime", "cpu_level", "install_channel"},
    },
    "windows": {
        "sys_platform": LOST_WITH_THE_PLATFORM,
        "sysconfig_platform": {"arch", "cpu_level"},
        "pointer_bits": {"arch", "cpu_level"},
        "windows_version": {"os_release", "cpu_level"},
        "windows_feature_present": {"cpu_level"},
        "wow64_machines": {"translation"},
        "python_version": {"python_in_range"},
        "implementation_name": {"python_build"},
        "gil_disabled": {"python_build"},
        "polars_plr_injected": {"polars_runtime", "cpu_level"},
        "sys_prefix": {"install_channel"},
        "realpath": {"install_channel"},
        "distribution": {"polars_runtime", "cpu_level", "python_in_range"},
        "getenv": {"polars_runtime", "cpu_level", "install_channel"},
    },
}


@pytest.mark.parametrize("host", sorted(HOSTS))
def test_the_failure_table_names_every_source_the_baseline_reads(host, tmp_path):
    recorded, called = recording(HOSTS[host](tmp_path))
    HostFactsReader(recorded).read(express_supported=lambda: EXPRESS[host])
    assert called - {"read_text"} == set(FAILURE_TABLES[host])


@pytest.mark.parametrize(
    ("host", "source"),
    [
        pytest.param(host, source, id=f"{host}-{source}")
        for host in sorted(FAILURE_TABLES)
        for source in sorted(FAILURE_TABLES[host])
    ],
)
def test_the_facts_a_failing_source_takes_with_it(tmp_path, host, source):
    sources = HOSTS[host](tmp_path)
    baseline = read(sources, express=EXPRESS[host])
    reading = read(
        dataclasses.replace(sources, **{source: _raises}), express=EXPRESS[host]
    )
    changed = {
        name
        for name in READING_FIELDS
        if getattr(reading, name) != getattr(baseline, name)
    }
    assert changed == FAILURE_TABLES[host][source]


@pytest.mark.parametrize(
    ("path", "unknown_facts"),
    [
        # The processor file also says whether an x86-64 machine runs x86 code natively.
        ("/proc/cpuinfo", {"cpu_level", "translation"}),
        ("/proc/sys/kernel/osrelease", {"wsl"}),
    ],
)
def test_an_unreadable_proc_file_takes_the_facts_that_read_it(
    tmp_path, path, unknown_facts
):
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
        for name in READING_FIELDS
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
    assert {name for name, _kind in reading.failed} <= set(READING_FIELDS)


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
    # Each file once, whatever limit or calling style a read uses: the translation and
    # the processor level both read the processor file, and they share one read.
    for path in ("/proc/cpuinfo", "/proc/sys/kernel/osrelease"):
        reads = {key: n for key, n in counts.items() if key[:2] == ("read_text", path)}
        assert sum(reads.values()) == 1, (path, reads)
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

    def always_failing(path: str, limit: int) -> str:
        attempts.append(path)
        raise OSError(errno.EIO, path)

    reader = HostFactsReader(
        dataclasses.replace(linux_host(tmp_path), read_text=always_failing)
    )
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    # The failed processor file is one failure the translation and the level share.
    assert ("cpu_level", "OSError") in second.failed
    assert ("translation", "OSError") in second.failed
    assert sorted(attempts) == ["/proc/cpuinfo", "/proc/sys/kernel/osrelease"]


class Counted:
    """A real distribution behind a proxy that counts what the reader asks of it.

    ``fail`` names the attributes whose read raises ``RuntimeError`` instead. ``reads``
    counts the files read through ``read_text``, by name: how often a reader opens the
    METADATA text itself.
    """

    def __init__(self, inner: PathDistribution, fail: Collection[str] = ()) -> None:
        self._inner = inner
        self._fail = frozenset(fail)
        self.asked: Counter = Counter()
        self.reads: Counter = Counter()

    def read_text(self, filename: str) -> Optional[str]:
        self.reads[filename] += 1
        if "read_text" in self._fail:
            raise RuntimeError("planted failure reading read_text")
        return self._inner.read_text(filename)

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
    # polars and the runtime in use are read once for both readings. The runtimes
    # polars would try only after it are never looked up: the first that loads decides.
    for name in ("polars", "polars-runtime-compat"):
        assert proxies[name].reads["METADATA"] == 1, name
    assert set(proxies) == {
        "polars",
        "polars-runtime-compat",
        "automated-security-helper",
    }
    # The flags file of the runtime in use is found once, and ASH's metadata is read
    # once, not once per reading.
    assert proxies["polars-runtime-compat"].asked["files"] == 1
    assert proxies["automated-security-helper"].reads["METADATA"] == 1


def test_a_new_reader_reads_the_distributions_again(tmp_path):
    sources, proxies = counted_sources(tmp_path, polars_site(tmp_path))
    HostFactsReader(sources).read(express_supported=lambda: True)
    HostFactsReader(sources).read(express_supported=lambda: True)
    assert proxies["polars"].reads["METADATA"] == 2
    assert proxies["automated-security-helper"].reads["METADATA"] == 2


def test_a_failed_version_read_is_remembered_not_retried(tmp_path):
    # Whichever way the version is asked for, it cannot be read: once is all it costs.
    unreadable = {"read_text", "version", "metadata"}
    sources, proxies = counted_sources(
        tmp_path, polars_site(tmp_path), fail={"polars": unreadable}
    )
    reader = HostFactsReader(sources)
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    assert ("polars_runtime", "RuntimeError") in second.failed
    assert (second.polars_runtime, second.cpu_level) == (UNKNOWN, UNKNOWN)
    assert proxies["polars"].reads["METADATA"] == 1


def test_a_failed_requires_python_read_is_remembered_not_retried(tmp_path):
    site = polars_site(tmp_path, ash=False)
    site.add_ash(requires_python="not a specifier")
    sources, proxies = counted_sources(tmp_path, site)
    reader = HostFactsReader(sources)
    first = reader.read(express_supported=lambda: True)
    second = reader.read(express_supported=lambda: True)
    assert first == second
    assert ("python_in_range", "InvalidSpecifier") in second.failed
    assert proxies["automated-security-helper"].reads["METADATA"] == 1


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
        executable=_raises,
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


def _is_type_checking_test(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _module_scope_imports(tree: ast.Module) -> set[str]:
    """The top-level names of the modules that importing the module loads.

    Every statement that runs at import counts, whatever block it is in: the body, the
    handlers, the else and the finally blocks of a try (the star form included), loops
    and their else blocks, with blocks, match cases and class bodies. What a function
    holds runs when it is called, and what a ``TYPE_CHECKING`` test guards does not run.
    """
    names: set[str] = set()

    def visit(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, ast.Import):
                names.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            elif isinstance(node, ast.If) and _is_type_checking_test(node.test):
                visit(node.orelse)
            else:
                for block in ("body", "orelse", "finalbody"):
                    visit(getattr(node, block, []))
                for handler in getattr(node, "handlers", []):
                    visit(handler.body)
                for case in getattr(node, "cases", []):
                    visit(case.body)

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


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # Every block of a statement that runs when the module is imported counts: a
        # handler, an else and a finally block as much as the try body (and the star
        # form of the handler), the else of a loop, and the body of a class.
        pytest.param(
            "try:\n    import a\nexcept ImportError:\n    import b\n",
            {"a", "b"},
            id="a-try-body-and-its-handler",
        ),
        pytest.param(
            "try:\n    pass\nexcept ValueError:\n    pass\nelse:\n    import a\n",
            {"a"},
            id="a-try-else",
        ),
        pytest.param(
            "try:\n    pass\nfinally:\n    import a\n", {"a"}, id="a-try-finally"
        ),
        pytest.param(
            "try:\n    pass\nexcept* ValueError:\n    import a\n",
            {"a"},
            id="a-star-handler",
        ),
        pytest.param(
            "try:\n    import a\nexcept ImportError:\n    if y:\n        import b\n",
            {"a", "b"},
            id="a-statement-in-a-handler",
        ),
        pytest.param("with open(f):\n    import a\n", {"a"}, id="a-with-body"),
        pytest.param(
            "for x in y:\n    import a\nelse:\n    import b\n",
            {"a", "b"},
            id="a-for-and-its-else",
        ),
        pytest.param(
            "while x:\n    import a\nelse:\n    import b\n",
            {"a", "b"},
            id="a-while-and-its-else",
        ),
        pytest.param("class C:\n    import a\n", {"a"}, id="a-class-body"),
        pytest.param(
            "match x:\n    case 1:\n        import a\n", {"a"}, id="a-match-case"
        ),
        pytest.param(
            "if x:\n    import a\nelif y:\n    import b\nelse:\n    import c\n",
            {"a", "b", "c"},
            id="every-branch-of-an-if",
        ),
        pytest.param(
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n    import a\nelse:\n    import b\n",
            {"typing", "b"},
            id="the-else-of-a-type-checking-block",
        ),
        # What runs only when it is called does not count.
        pytest.param("def f():\n    import a\n", set(), id="a-function"),
        pytest.param("async def f():\n    import a\n", set(), id="an-async-function"),
        pytest.param(
            "class C:\n    def f(self):\n        import a\n", set(), id="a-method"
        ),
        pytest.param(
            "try:\n    def f():\n        import a\nexcept ImportError:\n    pass\n",
            set(),
            id="a-function-in-a-try",
        ),
    ],
)
def test_the_import_walk_sees_every_statement_that_runs_when_the_module_is_imported(
    source, expected
):
    assert _module_scope_imports(ast.parse(source)) == expected


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
        "executable",
        "read_head",
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


def test_the_live_head_read_is_bounded_and_returns_the_bytes_as_they_are(tmp_path):
    target = tmp_path / "file"
    target.write_bytes(b"abc\xffdef-and-more")
    assert host_facts._live_read_head(str(target), 7) == b"abc\xffdef"
    assert host_facts._live_read_head(str(target), 4096) == b"abc\xffdef-and-more"
    with pytest.raises(FileNotFoundError):
        host_facts._live_read_head(str(tmp_path / "absent"), 10)


def test_the_live_executable_is_the_interpreters_and_empty_when_it_has_none(
    monkeypatch,
):
    monkeypatch.setattr(sys, "executable", "/opt/python/bin/python3")
    assert host_facts._live_executable() == "/opt/python/bin/python3"
    for none in ("", None):
        monkeypatch.setattr(sys, "executable", none)
        assert host_facts._live_executable() == ""


def test_the_live_distribution_lookup_answers_none_for_a_missing_name(
    tmp_path, monkeypatch
):
    site = Site(tmp_path)
    site.add("zz-planted-dist", "2.1")
    monkeypatch.syspath_prepend(str(site.root))
    found = host_facts._live_distribution("zz-planted-dist")
    assert found is not None and found.version == "2.1"
    assert host_facts._live_distribution("zz-no-such-dist-anywhere") is None
