"""The processor facts of the host reader, and the drift test against the locked runtime.

``cpu_level`` says how the host's x86-64 feature set compares with the two sets polars
builds for, and ``polars_runtime`` says which of polars' runtimes will load. The reader
imports nothing to decide either: the host's flags come from ``/proc/cpuinfo`` (Linux),
three ``machdep.cpu`` strings (macOS) or ``IsProcessorFeaturePresent`` (Windows), the
installed runtimes from ``importlib.metadata``, and each runtime's required flags from its
generated ``build_feature_flags.py``, read as text through the distribution's file list.

Every host input here is planted (the helpers are in ``test_host_facts.py``). The
macOS reading is a declared one, tested through fakes: the ``machdep.cpu`` strings below
have the shape Intel Macs print, and a real macOS lane pins the keys.

The last section is the drift test. It runs in the lane against the polars runtime the
lock installs and fails when the installed flags file differs from the declared set,
when the file moves, when it names a flag the name table lacks, or when polars'
own runtime selection no longer reads the way the reader mirrors it. Each failure is
shown on a copy of the real file with one flag added, one removed and the file unlisted.
The compatibility and 64-bit runtimes are checked the same way where they are installed;
a lane that installs ``polars[rtcompat]`` runs those two cases, and the others skip.
"""

from __future__ import annotations

import dataclasses
import errno
import importlib.metadata
import inspect
import platform
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

import pytest
from packaging.requirements import Requirement

from automated_security_helper.utils import host_facts
from automated_security_helper.utils.host_facts import (
    COMPAT_RUNTIME_FLAGS,
    DEFAULT_RUNTIME_FLAGS,
    FLAG_SPELLINGS,
    RUNTIME_FLAGS,
    UNKNOWN,
)
from tests.unit.utils.test_host_facts import (
    ALL_PRESENT,
    COMPAT_FLAGS_TEXT,
    DEFAULT_FLAGS_TEXT,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64,
    MAC_HASWELL_STRINGS,
    PF_AVX,
    PF_AVX2,
    PF_BMI2,
    PF_CX16,
    PF_SSE3,
    PF_SSE4_1,
    PF_SSE4_2,
    PF_SSSE3,
    SKYLAKE_FLAGS,
    Site,
    UnplantedRead,
    cpuinfo,
    linux_host,
    macos_host,
    polars_site,
    read,
    stand_in_matches,
    windows_host,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]

#: polars' two sets, spelled here from the release workflow's declaration (the
#: ``target-feature`` lines of ``release-python.yml`` at py-1.44.2): the default runtimes
#: (32 and 64) are built for the first, the compatibility runtime for the second.
WORKFLOW_DEFAULT = (
    "+sse3,+ssse3,+sse4.1,+sse4.2,+popcnt,+cmpxchg16b,"
    "+avx,+avx2,+fma,+bmi1,+bmi2,+lzcnt,+pclmulqdq,+movbe"
)
WORKFLOW_COMPAT = "+sse3,+ssse3,+sse4.1,+sse4.2,+popcnt,+cmpxchg16b"
DEFAULT_SET = (
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
COMPAT_SET = DEFAULT_SET[:6]

# --------------------------------------------------------------------------------------
# The declared sets and the name table
# --------------------------------------------------------------------------------------


def test_the_declared_sets_are_the_release_workflows_declaration():
    assert host_facts.split_build_flags(WORKFLOW_DEFAULT) == DEFAULT_SET
    assert host_facts.split_build_flags(WORKFLOW_COMPAT) == COMPAT_SET
    assert DEFAULT_RUNTIME_FLAGS == DEFAULT_SET
    assert COMPAT_RUNTIME_FLAGS == COMPAT_SET
    assert dict(RUNTIME_FLAGS) == {
        "runtime-32": DEFAULT_SET,
        "runtime-64": DEFAULT_SET,
        "compat": COMPAT_SET,
    }


def test_the_compatibility_set_is_the_first_six_flags_of_the_default_set():
    assert set(COMPAT_RUNTIME_FLAGS) < set(DEFAULT_RUNTIME_FLAGS)
    assert DEFAULT_RUNTIME_FLAGS[: len(COMPAT_RUNTIME_FLAGS)] == COMPAT_RUNTIME_FLAGS


def test_the_name_table_names_exactly_the_declared_flags():
    assert set(FLAG_SPELLINGS) == set(DEFAULT_SET)


def test_the_name_table_spells_each_flag_as_the_linux_kernel_does():
    # cpufeatures.h: the kernel prints polars' sse3, sse4.1, sse4.2, cmpxchg16b and
    # lzcnt as pni, sse4_1, sse4_2, cx16 and abm; every other flag keeps its name.
    kernel = {
        "sse3": "pni",
        "sse4.1": "sse4_1",
        "sse4.2": "sse4_2",
        "cmpxchg16b": "cx16",
        "lzcnt": "abm",
    }
    for flag in DEFAULT_SET:
        assert kernel.get(flag, flag) in FLAG_SPELLINGS[flag].linux, flag


def test_the_name_table_holds_the_windows_constants_the_documentation_lists():
    # IsProcessorFeaturePresent has constants for these eight and none for the other
    # six (FMA, BMI1, LZCNT, MOVBE, PCLMULQDQ, POPCNT).
    assert {flag: spelling.windows for flag, spelling in FLAG_SPELLINGS.items()} == {
        "sse3": 13,
        "cmpxchg16b": 14,
        "ssse3": 36,
        "sse4.1": 37,
        "sse4.2": 38,
        "avx": 39,
        "avx2": 40,
        "bmi2": 60,
        "popcnt": None,
        "fma": None,
        "bmi1": None,
        "lzcnt": None,
        "pclmulqdq": None,
        "movbe": None,
    }


def test_the_name_table_gives_every_flag_a_macos_feature_string_to_look_in():
    keys = {
        "machdep.cpu.features",
        "machdep.cpu.leaf7_features",
        "machdep.cpu.extfeatures",
    }
    for flag, spelling in FLAG_SPELLINGS.items():
        key, token = spelling.macos
        assert key in keys and token, flag


def test_the_runtime_choices_are_the_selector_names_polars_uses():
    assert dict(host_facts.RUNTIME_CHOICES) == {
        "compat": ("compat", "polars-runtime-compat"),
        "64": ("runtime-64", "polars-runtime-64"),
        "32": ("runtime-32", "polars-runtime-32"),
    }
    assert tuple(host_facts.DEFAULT_PREFERENCE) == ("compat", "64", "32")


# --------------------------------------------------------------------------------------
# The level, from what a host can report
# --------------------------------------------------------------------------------------


def reports(**overrides: Optional[bool]) -> dict[str, Optional[bool]]:
    """Every default flag present, then the overrides (``sse4_1`` for ``sse4.1``)."""
    base: dict[str, Optional[bool]] = dict.fromkeys(DEFAULT_SET, True)
    for name, value in overrides.items():
        base[name.replace("_", ".") if name.startswith("sse4_") else name] = value
    return base


@pytest.mark.parametrize(
    ("given", "level", "missing"),
    [
        (reports(), "full", ()),
        (reports(avx2=False), "compat-only", ("avx2",)),
        (
            reports(avx2=False, fma=False, bmi2=False),
            "compat-only",
            ("avx2", "fma", "bmi2"),
        ),
        (reports(movbe=False), "compat-only", ("movbe",)),
        (reports(sse4_2=False), "below-compat", ("sse4.2",)),
        (reports(popcnt=False, avx=False), "below-compat", ("popcnt", "avx")),
        (reports(sse3=False), "below-compat", ("sse3",)),
        # A compatibility flag absent decides below-compat even beside a default-only one.
        (reports(sse4_1=False, avx2=False), "below-compat", ("sse4.1", "avx2")),
        # A flag the host could not be asked is not an absent flag.
        (reports(avx2=None), "unknown", ()),
        (reports(movbe=None), "unknown", ()),
        (reports(popcnt=None), "unknown", ()),
        # ... but an absent one beside it still decides.
        (reports(avx2=False, movbe=None), "compat-only", ("avx2",)),
        (reports(sse4_2=False, movbe=None), "below-compat", ("sse4.2",)),
        ({}, "unknown", ()),
    ],
)
def test_the_level_is_decided_by_the_flags_the_host_reports(given, level, missing):
    assert host_facts.cpu_level_from_reports(given) == (level, missing)


def test_flags_a_platform_cannot_report_at_all_do_not_stop_full():
    # Windows has no constant for six of the flags: they are not in the mapping.
    windows_like = dict.fromkeys(
        ("sse3", "cmpxchg16b", "ssse3", "sse4.1", "sse4.2", "avx", "avx2"), True
    )
    assert host_facts.cpu_level_from_reports(windows_like) == ("full", ())


def test_full_needs_the_decisive_flag_to_have_been_reported():
    # Before the AVX constants answer, the level cannot be told from what is left.
    old_windows = {"sse3": True, "cmpxchg16b": True}
    assert host_facts.cpu_level_from_reports(old_windows) == (UNKNOWN, ())


def test_the_missing_flags_come_in_the_order_polars_lists_them():
    given = reports(movbe=False, avx2=False, fma=False, lzcnt=False)
    level, missing = host_facts.cpu_level_from_reports(given)
    assert (level, missing) == ("compat-only", ("avx2", "fma", "lzcnt", "movbe"))


# --------------------------------------------------------------------------------------
# Linux: /proc/cpuinfo
# --------------------------------------------------------------------------------------

SANDY_BRIDGE_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
    "dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx rdtscp lm constant_tsc "
    "arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni "
    "pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 cx16 xtpr pdcm pcid sse4_1 "
    "sse4_2 x2apic popcnt tsc_deadline_timer aes xsave avx lahf_lm epb tpr_shadow vnmi "
    "flexpriority ept vpid xsaveopt dtherm ida arat pln pts"
)
NEHALEM_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
    "dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx rdtscp lm constant_tsc "
    "arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni "
    "dtes64 monitor ds_cpl vmx est tm2 ssse3 cx16 xtpr pdcm pcid sse4_1 sse4_2 popcnt "
    "lahf_lm tpr_shadow vnmi flexpriority ept vpid dtherm ida"
)
ATOM_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
    "dts acpi mmx fxsr sse sse2 ss ht tm pbe nx lm constant_tsc arch_perfmon pebs bts "
    "nopl cpuid aperfmperf pni dtes64 monitor ds_cpl est tm2 ssse3 cx16 xtpr pdcm "
    "movbe lahf_lm dtherm"
)
CORE2_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
    "dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx lm constant_tsc arch_perfmon "
    "pebs bts rep_good nopl cpuid aperfmperf pni dtes64 monitor ds_cpl vmx smx est tm2 "
    "ssse3 cx16 xtpr pdcm sse4_1 lahf_lm pti tpr_shadow vnmi flexpriority vpid dtherm"
)
AMD_ZEN_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
    "mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc "
    "rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf pni pclmulqdq monitor "
    "ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand "
    "lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch "
    "osvw ibs skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx "
    "cpb cat_l3 cdp_l3 hw_pstate ssbd mba ibrs ibpb stibp vmmcall fsgsbase bmi1 avx2 "
    "smep bmi2 cqm rdt_a rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec "
    "xgetbv1 xsaves cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local clzero irperf "
    "xsaveerptr rdpru wbnoinvd arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean "
    "flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif "
    "v_spec_ctrl umip rdpid overflow_recov succor smca"
)
AMD_BULLDOZER_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
    "mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc "
    "rep_good nopl nonstop_tsc cpuid extd_apicid aperfmperf pni pclmulqdq monitor "
    "ssse3 cx16 sse4_1 sse4_2 popcnt aes xsave avx lahf_lm cmp_legacy svm extapic "
    "cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw ibs xop skinit wdt lwp fma4 "
    "nodeid_msr topoext perfctr_core perfctr_nb cpb hw_pstate vmmcall arat npt lbrv "
    "svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter "
    "pfthreshold"
)
#: polars' own spellings, which no kernel prints, are read as present too.
POLARS_SPELLED_FLAGS = (
    "fpu sse2 lm sse3 ssse3 sse4.1 sse4.2 popcnt cmpxchg16b avx avx2 fma bmi1 bmi2 "
    "lzcnt pclmulqdq movbe"
)


@pytest.mark.parametrize(
    ("flags", "level", "missing"),
    [
        pytest.param(SKYLAKE_FLAGS, "full", (), id="an-avx2-class-intel-part"),
        pytest.param(AMD_ZEN_FLAGS, "full", (), id="an-amd-zen-part-abm-is-lzcnt"),
        pytest.param(POLARS_SPELLED_FLAGS, "full", (), id="polars-own-spellings"),
        pytest.param(
            SANDY_BRIDGE_FLAGS,
            "compat-only",
            ("avx2", "fma", "bmi1", "bmi2", "lzcnt", "movbe"),
            id="a-sandy-bridge-class-part",
        ),
        pytest.param(
            NEHALEM_FLAGS,
            "compat-only",
            ("avx", "avx2", "fma", "bmi1", "bmi2", "lzcnt", "pclmulqdq", "movbe"),
            id="a-nehalem-class-part-without-avx",
        ),
        pytest.param(
            AMD_BULLDOZER_FLAGS,
            "compat-only",
            ("avx2", "fma", "bmi1", "bmi2", "movbe"),
            id="an-amd-bulldozer-part-fma4-is-not-fma",
        ),
        pytest.param(
            CORE2_FLAGS,
            "below-compat",
            (
                "sse4.2",
                "popcnt",
                "avx",
                "avx2",
                "fma",
                "bmi1",
                "bmi2",
                "lzcnt",
                "pclmulqdq",
                "movbe",
            ),
            id="a-core2-class-part-without-sse4.2",
        ),
        pytest.param(
            ATOM_FLAGS,
            "below-compat",
            (
                "sse4.1",
                "sse4.2",
                "popcnt",
                "avx",
                "avx2",
                "fma",
                "bmi1",
                "bmi2",
                "lzcnt",
                "pclmulqdq",
            ),
            id="an-old-atom-class-part-without-avx",
        ),
    ],
)
def test_the_level_of_a_planted_proc_cpuinfo(tmp_path, flags, level, missing):
    reading = read(linux_host(tmp_path, cpuinfo_text=cpuinfo(flags)))
    assert (reading.cpu_level, reading.cpu_missing_flags) == (level, missing)


def test_the_kernel_spellings_are_what_the_reader_looks_for(tmp_path):
    # Delete one kernel spelling at a time from a full part: each turns its own polars
    # flag absent and no other.
    pairs = {
        "pni": "sse3",
        "sse4_1": "sse4.1",
        "sse4_2": "sse4.2",
        "cx16": "cmpxchg16b",
        "abm": "lzcnt",
    }
    for kernel_name, polars_name in pairs.items():
        flags = " ".join(f for f in SKYLAKE_FLAGS.split() if f != kernel_name)
        reading = read(linux_host(tmp_path / kernel_name, cpuinfo_text=cpuinfo(flags)))
        assert reading.cpu_missing_flags == (polars_name,), kernel_name


def test_only_the_first_flags_line_counts(tmp_path):
    full_first = cpuinfo(SKYLAKE_FLAGS, later_flags=NEHALEM_FLAGS)
    old_first = cpuinfo(NEHALEM_FLAGS, later_flags=SKYLAKE_FLAGS)
    assert read(linux_host(tmp_path / "a", cpuinfo_text=full_first)).cpu_level == "full"
    assert (
        read(linux_host(tmp_path / "b", cpuinfo_text=old_first)).cpu_level
        == "compat-only"
    )


ARM_CPUINFO = (
    "processor\t: 0\n"
    "BogoMIPS\t: 50.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\n"
    "CPU implementer\t: 0x41\n"
)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("processor\t: 0\nmodel name\t: x\n", id="no-flags-line"),
        pytest.param(ARM_CPUINFO, id="an-arm-file-under-an-x86-looking-process"),
        pytest.param("processor\t: 0\nflags\t\t:\n", id="an-empty-flags-line"),
        pytest.param(
            "processor\t: 0\nflags\t\t: fpu vme de\n", id="no-long-mode-or-sse2"
        ),
        pytest.param("flags2\t: " + SKYLAKE_FLAGS + "\n", id="another-key"),
        pytest.param(
            "x" * 70000 + "\nflags\t\t: " + SKYLAKE_FLAGS + "\n",
            id="beyond-the-read-bound",
        ),
        pytest.param("flags: " + SKYLAKE_FLAGS.replace(" lm ", " "), id="no-long-mode"),
    ],
)
def test_an_unreadable_proc_cpuinfo_reads_unknown(tmp_path, text):
    reading = read(linux_host(tmp_path, cpuinfo_text=text))
    assert reading.cpu_level == UNKNOWN
    assert reading.cpu_missing_flags == ()
    assert stand_in_matches(reading) == []


@pytest.mark.parametrize(
    "line",
    [
        "flags\t\t: " + SKYLAKE_FLAGS,
        "flags: " + SKYLAKE_FLAGS,
        "  flags  :   " + SKYLAKE_FLAGS + "   ",
    ],
)
def test_the_flags_key_is_matched_by_name_not_by_layout(tmp_path, line):
    text = "processor\t: 0\n" + line + "\nbugs\t\t: x\n"
    assert read(linux_host(tmp_path, cpuinfo_text=text)).cpu_level == "full"


def test_the_processor_level_is_not_read_off_x86(tmp_path):
    # /proc/cpuinfo stays unplanted for these: a read of it raises UnplantedRead.
    sources = linux_host(tmp_path)
    inner = sources.read_text

    def only_the_kernel_release(path: str, limit: int) -> str:
        if path == "/proc/sys/kernel/osrelease":
            return inner(path, limit)
        raise UnplantedRead(path)

    for machine, level in (("aarch64", "n/a"), ("ppc64le", "n/a"), ("", UNKNOWN)):
        reading = read(
            dataclasses.replace(
                sources, machine=lambda m=machine: m, read_text=only_the_kernel_release
            )
        )
        assert reading.cpu_level == level, machine
        # The runtime it would have been judged against is still named.
        assert reading.polars_runtime == "runtime-32"


# --------------------------------------------------------------------------------------
# macOS: the machdep.cpu feature strings (a declared reading, through fakes)
# --------------------------------------------------------------------------------------

SANDY_BRIDGE_MAC = {
    "machdep.cpu.features": (
        "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE36 CLFSH "
        "DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE SSE3 PCLMULQDQ DTES64 MON DSCPL VMX "
        "SMX EST TM2 SSSE3 CX16 TPR PDCM SSE4.1 SSE4.2 x2APIC POPCNT AES PCID XSAVE "
        "OSXSAVE TSCTMR AVX1.0"
    ),
    "machdep.cpu.leaf7_features": "",
    "machdep.cpu.extfeatures": "SYSCALL XD EM64T LAHF RDTSCP TSCI",
}
#: A shape a translated process could see: SSE4.2 and no AVX at all.
ROSETTA_WITHOUT_AVX = {
    "machdep.cpu.features": (
        "FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE36 CLFSH "
        "MMX FXSR SSE SSE2 SSE3 PCLMULQDQ SSSE3 CX16 SSE4.1 SSE4.2 MOVBE POPCNT AES"
    ),
    "machdep.cpu.leaf7_features": "",
    "machdep.cpu.extfeatures": "SYSCALL XD EM64T LAHF LZCNT PREFETCHW RDTSCP",
}


def _without(strings: Mapping[str, Any], key: str, value: Any) -> dict[str, Any]:
    return {**strings, key: value}


@pytest.mark.parametrize(
    ("strings", "level", "missing"),
    [
        pytest.param(MAC_HASWELL_STRINGS, "full", (), id="haswell-class"),
        pytest.param(
            SANDY_BRIDGE_MAC,
            "compat-only",
            ("avx2", "fma", "bmi1", "bmi2", "lzcnt", "movbe"),
            id="sandy-bridge-class-with-an-empty-leaf7-string",
        ),
        pytest.param(
            ROSETTA_WITHOUT_AVX,
            "compat-only",
            ("avx", "avx2", "fma", "bmi1", "bmi2"),
            id="a-translated-process-without-avx",
        ),
        # A leaf7 key that does not exist leaves AVX2, BMI1 and BMI2 unasked, but the
        # feature string already shows the part lacks FMA and MOVBE.
        pytest.param(
            _without(
                SANDY_BRIDGE_MAC,
                "machdep.cpu.leaf7_features",
                OSError(errno.ENOENT, "none"),
            ),
            "compat-only",
            ("fma", "lzcnt", "movbe"),
            id="sandy-bridge-class-with-no-leaf7-key",
        ),
        # With nothing absent in what could be read, the level is not guessed.
        pytest.param(
            _without(
                MAC_HASWELL_STRINGS,
                "machdep.cpu.leaf7_features",
                OSError(errno.ENOENT, "none"),
            ),
            UNKNOWN,
            (),
            id="a-capable-part-whose-leaf7-key-cannot-be-read",
        ),
        pytest.param(
            _without(
                MAC_HASWELL_STRINGS,
                "machdep.cpu.extfeatures",
                OSError(errno.EPERM, "denied"),
            ),
            UNKNOWN,
            (),
            id="a-capable-part-whose-extfeatures-key-cannot-be-read",
        ),
        pytest.param(
            _without(
                MAC_HASWELL_STRINGS,
                "machdep.cpu.features",
                OSError(errno.ENOENT, "none"),
            ),
            UNKNOWN,
            (),
            id="a-part-whose-features-key-cannot-be-read",
        ),
        pytest.param(
            _without(MAC_HASWELL_STRINGS, "machdep.cpu.features", ""),
            UNKNOWN,
            (),
            id="an-empty-features-string",
        ),
    ],
)
def test_the_level_of_planted_macos_feature_strings(tmp_path, strings, level, missing):
    reading = read(macos_host(tmp_path, strings=strings))
    assert (reading.cpu_level, reading.cpu_missing_flags) == (level, missing)


def test_macos_feature_tokens_are_matched_whole_and_without_regard_to_case(tmp_path):
    # BMI1 and AVX2 appear only inside longer tokens, which are other features; BMI2
    # is spelled in lower case, which is still the feature.
    strings = _without(
        MAC_HASWELL_STRINGS, "machdep.cpu.leaf7_features", "XBMI1 AVX2X bmi2 SMEP"
    )
    reading = read(macos_host(tmp_path, strings=strings))
    assert reading.cpu_missing_flags == ("avx2", "bmi1")


def test_a_translated_process_with_the_old_feature_set_matches_both_rows(tmp_path):
    reading = read(macos_host(tmp_path, translated=1, strings=ROSETTA_WITHOUT_AVX))
    assert stand_in_matches(reading) == [
        "host.cpu.below-polars-runtime",
        "host.translation.rosetta",
    ]


def test_a_translated_process_that_sees_the_full_set_matches_only_the_translation_row(
    tmp_path,
):
    reading = read(macos_host(tmp_path, translated=1))
    assert reading.cpu_level == "full"
    assert stand_in_matches(reading) == ["host.translation.rosetta"]


# --------------------------------------------------------------------------------------
# Windows: IsProcessorFeaturePresent
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("build", "asked"),
    [
        (18363, {PF_SSE3, PF_CX16}),
        (19040, {PF_SSE3, PF_CX16}),
        (19041, {PF_SSE3, PF_CX16, PF_SSSE3, PF_SSE4_1, PF_SSE4_2, PF_AVX, PF_AVX2}),
        (22631, {PF_SSE3, PF_CX16, PF_SSSE3, PF_SSE4_1, PF_SSE4_2, PF_AVX, PF_AVX2}),
        (26099, {PF_SSE3, PF_CX16, PF_SSSE3, PF_SSE4_1, PF_SSE4_2, PF_AVX, PF_AVX2}),
        (
            26100,
            {
                PF_SSE3,
                PF_CX16,
                PF_SSSE3,
                PF_SSE4_1,
                PF_SSE4_2,
                PF_AVX,
                PF_AVX2,
                PF_BMI2,
            },
        ),
        (
            27000,
            {
                PF_SSE3,
                PF_CX16,
                PF_SSSE3,
                PF_SSE4_1,
                PF_SSE4_2,
                PF_AVX,
                PF_AVX2,
                PF_BMI2,
            },
        ),
    ],
)
def test_the_reader_asks_only_what_the_running_build_can_answer(tmp_path, build, asked):
    seen: list[int] = []
    read(windows_host(tmp_path, build=build, asked=seen), express=False)
    assert set(seen) == asked
    assert len(seen) == len(set(seen)), "a constant was asked twice"
    assert set(host_facts.windows_constants_for_build(build)) == asked


@pytest.mark.parametrize(
    ("build", "present", "level", "missing"),
    [
        pytest.param(26100, ALL_PRESENT, "full", (), id="windows-11-24h2-all-present"),
        pytest.param(
            22631,
            ALL_PRESENT - {PF_BMI2},
            "full",
            (),
            id="bmi2-is-not-asked-before-24h2",
        ),
        pytest.param(
            22631, ALL_PRESENT - {PF_AVX2}, "compat-only", ("avx2",), id="no-avx2"
        ),
        pytest.param(
            22631,
            ALL_PRESENT - {PF_AVX, PF_AVX2},
            "compat-only",
            ("avx", "avx2"),
            id="no-avx-at-all",
        ),
        pytest.param(
            26100,
            ALL_PRESENT - {PF_BMI2},
            "compat-only",
            ("bmi2",),
            id="no-bmi2-on-24h2",
        ),
        pytest.param(
            22631,
            ALL_PRESENT - {PF_SSE4_2},
            "below-compat",
            ("sse4.2",),
            id="no-sse4.2",
        ),
        pytest.param(
            19041, ALL_PRESENT - {PF_SSSE3}, "below-compat", ("ssse3",), id="no-ssse3"
        ),
        pytest.param(
            22631,
            ALL_PRESENT - {PF_CX16},
            "below-compat",
            ("cmpxchg16b",),
            id="no-cx16",
        ),
        # Before 2004 the AVX constants answer nothing: with the old two present the
        # level is not guessed, and with one absent it is still below-compat.
        pytest.param(
            18363, {PF_SSE3, PF_CX16}, UNKNOWN, (), id="windows-10-1909-capable"
        ),
        pytest.param(
            18363, {PF_CX16}, "below-compat", ("sse3",), id="windows-10-1909-no-sse3"
        ),
        pytest.param(
            19040,
            {PF_SSE3},
            "below-compat",
            ("cmpxchg16b",),
            id="one-build-before-2004",
        ),
    ],
)
def test_the_level_of_a_planted_windows_host(tmp_path, build, present, level, missing):
    reading = read(windows_host(tmp_path, build=build, present=present), express=False)
    assert (reading.cpu_level, reading.cpu_missing_flags) == (level, missing)


def test_an_arm64_windows_host_asks_for_no_processor_feature(tmp_path):
    seen: list[int] = []
    sources = windows_host(
        tmp_path,
        platform_name="win-arm64",
        wow64=(0, IMAGE_FILE_MACHINE_ARM64),
        asked=seen,
    )
    reading = read(sources, express=False)
    assert (reading.arch, reading.cpu_level) == ("arm64", "n/a")
    assert seen == []


def test_an_emulated_x64_process_is_judged_by_what_it_sees(tmp_path):
    reading = read(
        windows_host(
            tmp_path,
            present=ALL_PRESENT - {PF_AVX2},
            wow64=(IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64),
        ),
        express=False,
    )
    assert reading.cpu_level == "compat-only"
    assert stand_in_matches(reading) == [
        "host.cpu.below-polars-runtime",
        "host.translation.x64-on-arm64",
    ]


# --------------------------------------------------------------------------------------
# The runtime polars will load
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("installed", "force", "prefer", "expected"),
    [
        pytest.param((), None, None, ("absent", None), id="none-installed"),
        pytest.param(("32",), None, None, ("runtime-32", "32"), id="only-32"),
        pytest.param(("64",), None, None, ("runtime-64", "64"), id="only-64"),
        pytest.param(("compat",), None, None, ("compat", "compat"), id="only-compat"),
        pytest.param(("32", "64"), None, None, ("runtime-64", "64"), id="64-before-32"),
        pytest.param(
            ("32", "compat"), None, None, ("compat", "compat"), id="compat-first"
        ),
        pytest.param(
            ("32", "64", "compat"),
            None,
            None,
            ("compat", "compat"),
            id="compat-over-both",
        ),
        pytest.param(
            ("32", "64", "compat"), "32", None, ("runtime-32", "32"), id="forced-32"
        ),
        pytest.param(
            ("32", "64", "compat"), "64", None, ("runtime-64", "64"), id="forced-64"
        ),
        pytest.param(
            ("32", "64", "compat"),
            "compat",
            None,
            ("compat", "compat"),
            id="forced-compat",
        ),
        # polars imports the forced runtime and nothing else: not installed, no runtime.
        pytest.param(
            ("32",), "64", None, ("absent", None), id="forced-but-not-installed"
        ),
        pytest.param(
            ("32", "compat"), "bogus", None, (UNKNOWN, None), id="forced-bogus"
        ),
        # The variable is read as "set" even when empty, and an empty name is invalid.
        pytest.param(("32", "compat"), "", None, (UNKNOWN, None), id="forced-empty"),
        pytest.param(
            ("32", "compat"), None, "32", ("runtime-32", "32"), id="preferred-32"
        ),
        pytest.param(
            ("32", "compat"),
            None,
            "64",
            ("compat", "compat"),
            id="preferred-64-not-installed",
        ),
        pytest.param(
            ("32",), None, "64", ("runtime-32", "32"), id="preferred-then-default"
        ),
        pytest.param(
            ("32", "compat"), None, "bogus", (UNKNOWN, None), id="preferred-bogus"
        ),
        pytest.param(("32", "compat"), None, "", (UNKNOWN, None), id="preferred-empty"),
        # A forced runtime is the only one tried, and the preference is never read.
        pytest.param(
            ("32", "compat"),
            "32",
            "bogus",
            ("runtime-32", "32"),
            id="force-ignores-prefer",
        ),
    ],
)
def test_the_runtime_polars_picks_from_what_is_installed(
    installed, force, prefer, expected
):
    runtimes = dict.fromkeys(installed, "1.44.2")
    chosen = host_facts.choose_runtime(
        "1.44.2", runtimes, force=force, prefer=prefer, injected=False
    )
    assert chosen == expected


@pytest.mark.parametrize(
    ("polars", "runtimes", "expected"),
    [
        pytest.param(None, {"32": "1.44.2"}, (UNKNOWN, None), id="polars-missing"),
        pytest.param("1.32.9", {"32": "1.32.9"}, (UNKNOWN, None), id="below-the-range"),
        pytest.param(
            "2.0.0", {"32": "2.0.0"}, (UNKNOWN, None), id="at-the-excluded-bound"
        ),
        pytest.param(
            "2.0.0rc1", {"32": "2.0.0rc1"}, (UNKNOWN, None), id="prerelease-of-it"
        ),
        pytest.param("2.3.1", {"32": "2.3.1"}, (UNKNOWN, None), id="above-the-range"),
        pytest.param("garbage", {"32": "garbage"}, (UNKNOWN, None), id="not-a-version"),
        pytest.param(
            "1.33.0", {}, ("absent", None), id="the-first-version-in-range-no-runtime"
        ),
        pytest.param(
            "1.99.4", {"32": "1.99.4"}, ("runtime-32", "32"), id="the-last-minor"
        ),
        # A runtime of another version than polars is skipped, as polars skips it.
        pytest.param(
            "1.44.2", {"32": "1.44.1"}, ("absent", None), id="only-a-mismatch"
        ),
        pytest.param(
            "1.44.2",
            {"compat": "1.44.1", "32": "1.44.2"},
            ("runtime-32", "32"),
            id="a-mismatch-then-a-match",
        ),
        pytest.param(
            "1.35.0b1",
            {"32": "1.35.0b1"},
            ("runtime-32", "32"),
            id="prerelease-in-range",
        ),
    ],
)
def test_the_range_and_the_version_match_polars_applies(polars, runtimes, expected):
    chosen = host_facts.choose_runtime(
        polars, runtimes, force=None, prefer=None, injected=False
    )
    assert chosen == expected


def test_an_injected_runtime_means_the_reader_cannot_know_what_loads():
    chosen = host_facts.choose_runtime(
        "1.44.2", {"32": "1.44.2"}, force=None, prefer=None, injected=True
    )
    assert chosen == (UNKNOWN, None)


def with_env(sources: Any, **environment: str) -> Any:
    inner = sources.getenv
    return dataclasses.replace(
        sources, getenv=lambda name: environment.get(name, inner(name))
    )


def test_the_reader_applies_the_two_variables_per_reading(tmp_path):
    site = polars_site(
        tmp_path, runtimes={"compat": COMPAT_FLAGS_TEXT, "32": DEFAULT_FLAGS_TEXT}
    )
    sources = linux_host(tmp_path, site=site)
    assert read(sources).polars_runtime == "compat"
    assert read(with_env(sources, POLARS_FORCE_PKG="32")).polars_runtime == "runtime-32"
    assert (
        read(with_env(sources, POLARS_PREFER_PKG="32")).polars_runtime == "runtime-32"
    )
    assert read(with_env(sources, POLARS_FORCE_PKG="bogus")).polars_runtime == UNKNOWN


def test_a_runtime_that_is_not_installed_reads_absent_and_names_no_level(tmp_path):
    site = polars_site(tmp_path, runtimes={})
    reading = read(linux_host(tmp_path, site=site))
    assert reading.polars_runtime == "absent"
    assert reading.cpu_level == UNKNOWN
    assert stand_in_matches(reading) == []


def test_polars_missing_reads_unknown_for_both_facts(tmp_path):
    site = polars_site(tmp_path, polars=None, runtimes={})
    reading = read(linux_host(tmp_path, site=site))
    assert (reading.polars_runtime, reading.cpu_level) == (UNKNOWN, UNKNOWN)
    assert reading.failed == ()


def test_a_polars_outside_the_declared_range_reads_unknown_for_both_facts(tmp_path):
    site = polars_site(tmp_path, polars="2.1.0")
    reading = read(linux_host(tmp_path, site=site))
    assert (reading.polars_runtime, reading.cpu_level) == (UNKNOWN, UNKNOWN)


def test_the_range_polars_is_read_against_is_the_one_pyproject_declares():
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = [
        Requirement(text)
        for text in project["project"]["dependencies"]
        if Requirement(text).name == "polars"
    ]
    assert len(declared) == 1
    low = ".".join(str(part) for part in host_facts.POLARS_MIN_VERSION)
    high = ".".join(str(part) for part in host_facts.POLARS_BELOW_VERSION)
    assert {str(spec) for spec in declared[0].specifier} == {f">={low}", f"<{high}"}


# --------------------------------------------------------------------------------------
# The level is judged against the runtime in use, once its flags file is the declared set
# --------------------------------------------------------------------------------------


def test_the_compat_runtime_is_judged_by_its_own_file(tmp_path):
    site = polars_site(tmp_path, runtimes={"compat": COMPAT_FLAGS_TEXT})
    reading = read(
        linux_host(tmp_path, site=site, cpuinfo_text=cpuinfo(SANDY_BRIDGE_FLAGS))
    )
    assert (reading.polars_runtime, reading.cpu_level) == ("compat", "compat-only")
    # A compat-only part on the compatibility runtime is the polyfill row, not row 1.
    assert stand_in_matches(reading) == ["host.cpu.polars-compat-runtime"]


def test_a_part_below_the_compat_set_still_raises_row_one_on_the_compat_runtime(
    tmp_path,
):
    site = polars_site(tmp_path, runtimes={"compat": COMPAT_FLAGS_TEXT})
    reading = read(linux_host(tmp_path, site=site, cpuinfo_text=cpuinfo(ATOM_FLAGS)))
    assert (reading.polars_runtime, reading.cpu_level) == ("compat", "below-compat")
    assert stand_in_matches(reading) == ["host.cpu.below-polars-runtime"]


def test_an_installed_file_that_differs_from_the_declared_set_leaves_the_level_unknown(
    tmp_path,
):
    changed_files = (
        DEFAULT_FLAGS_TEXT.replace(",+movbe", ""),
        DEFAULT_FLAGS_TEXT.replace('+movbe"', '+movbe,+avx512f"'),
        COMPAT_FLAGS_TEXT,
        'BUILD_FEATURE_FLAGS = ""\n',
    )
    for index, text in enumerate(changed_files):
        root = tmp_path / f"case-{index}"
        site = polars_site(root, runtimes={"32": text})
        reading = read(linux_host(root, site=site, cpuinfo_text=cpuinfo(NEHALEM_FLAGS)))
        # The runtime is still named; the level is not guessed against a changed set.
        assert reading.polars_runtime == "runtime-32", index
        assert reading.cpu_level == UNKNOWN, index
        assert stand_in_matches(reading) == [], index


@pytest.mark.parametrize(
    "case",
    ["not-listed", "no-file", "unparsable"],
)
def test_a_runtime_whose_flags_file_cannot_be_read_leaves_the_level_unknown(
    tmp_path, case
):
    site = Site(tmp_path)
    site.add("polars", "1.44.2")
    if case == "not-listed":
        site.add_runtime("32", DEFAULT_FLAGS_TEXT, listed=False)
    elif case == "no-file":
        site.add_runtime("32", None)
    else:
        site.add_runtime("32", "BUILD_FEATURE_FLAGS = (\n")
    site.add_ash()
    reading = read(linux_host(tmp_path, site=site, cpuinfo_text=cpuinfo(NEHALEM_FLAGS)))
    assert reading.polars_runtime == "runtime-32"
    assert reading.cpu_level == UNKNOWN


# --------------------------------------------------------------------------------------
# Must-flag and must-not-flag: the same fixture, a capable part and an old one
# --------------------------------------------------------------------------------------


def test_the_same_fixture_with_the_level_set_to_compat_only_raises_row_one(tmp_path):
    sources = linux_host(tmp_path)
    capable = read(sources)
    assert (capable.cpu_level, stand_in_matches(capable)) == ("full", [])
    old = read(dataclasses.replace(sources, read_text=_old_part(sources)))
    assert old.cpu_level == "compat-only"
    assert stand_in_matches(old) == ["host.cpu.below-polars-runtime"]
    assert old.cpu_missing_flags == ("avx2", "fma", "bmi1", "bmi2", "lzcnt", "movbe")


def _old_part(sources: Any) -> Callable[[str, int], str]:
    inner = sources.read_text

    def read_text(path: str, limit: int) -> str:
        if path == "/proc/cpuinfo":
            return cpuinfo(SANDY_BRIDGE_FLAGS)[:limit]
        return inner(path, limit)

    return read_text


def test_the_same_old_part_with_its_cpuinfo_unreadable_raises_nothing(tmp_path):
    sources = linux_host(tmp_path)

    def broken(path: str, limit: int) -> str:
        if path == "/proc/cpuinfo":
            raise OSError(errno.EIO, path)
        return sources.read_text(path, limit)

    reading = read(dataclasses.replace(sources, read_text=broken))
    assert reading.cpu_level == UNKNOWN
    assert stand_in_matches(reading) == []


# --------------------------------------------------------------------------------------
# The flags file, read as text
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("+sse3,+ssse3", ("sse3", "ssse3")),
        ("+sse3,-avx,+avx2", ("sse3", "avx2")),
        ("+sse3,+ctr-static,+avx", ("sse3", "avx")),
        ("", ()),
        (",,+sse3,,", ("sse3",)),
        ("++sse3", ("sse3",)),
        ("sse3", ("sse3",)),
        ("-sse3", ()),
        ("+ctr-static", ()),
    ],
)
def test_the_build_flags_are_split_the_way_polars_splits_them(value, expected):
    assert host_facts.split_build_flags(value) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (DEFAULT_FLAGS_TEXT, DEFAULT_SET),
        (COMPAT_FLAGS_TEXT, COMPAT_SET),
        ("BUILD_FEATURE_FLAGS = '+sse3,+avx'\n", ("sse3", "avx")),
        ('# generated\n\nBUILD_FEATURE_FLAGS = "+sse3"\n', ("sse3",)),
        ('BUILD_FEATURE_FLAGS: str = "+sse3"\n', ("sse3",)),
        ('BUILD_FEATURE_FLAGS = "+sse3"\nBUILD_FEATURE_FLAGS = "+avx"\n', ("avx",)),
        ('BUILD_FEATURE_FLAGS = ""\n', ()),
        # Read as text: whatever follows is never run.
        ('BUILD_FEATURE_FLAGS = "+sse3"\nraise RuntimeError("imported")\n', ("sse3",)),
        ("BUILD_FEATURE_FLAGS = ('+sse3' '+avx')\n", None),
        ("BUILD_FEATURE_FLAGS = 5\n", None),
        ('BUILD_FEATURE_FLAGS = ["+sse3"]\n', None),
        ('flags = "+sse3"\n', None),
        ("def f():\n    BUILD_FEATURE_FLAGS = '+sse3'\n", None),
        ("BUILD_FEATURE_FLAGS = (\n", None),
        ("", None),
        ("\x00\x01", None),
    ],
)
def test_the_flags_file_is_parsed_as_an_assignment_never_run(text, expected):
    assert host_facts.parse_flags_file(text) == expected


def _dist(tmp_path: Path, text: Optional[str], *, listed: bool = True):
    return Site(tmp_path).add_runtime("32", text, listed=listed)


def test_the_flags_come_through_the_distributions_file_list(tmp_path):
    assert (
        host_facts.read_runtime_flags(_dist(tmp_path, DEFAULT_FLAGS_TEXT))
        == DEFAULT_SET
    )


@pytest.mark.parametrize(
    "case",
    [
        "not-in-the-file-list",
        "no-such-file",
        "no-record-at-all",
        "another-package-directory",
        "too-large",
    ],
)
def test_a_flags_file_the_reader_cannot_find_or_trust_reads_as_none(tmp_path, case):
    site = Site(tmp_path)
    if case == "not-in-the-file-list":
        dist = site.add_runtime("32", DEFAULT_FLAGS_TEXT, listed=False)
    elif case == "no-such-file":
        dist = site.add_runtime("32", None)
    elif case == "no-record-at-all":
        dist = site.add("polars-runtime-32", "1.44.2")
    elif case == "another-package-directory":
        dist = site.add(
            "polars-runtime-32",
            "1.44.2",
            files={"somewhere_else/build_feature_flags.py": DEFAULT_FLAGS_TEXT},
        )
    else:
        padded = DEFAULT_FLAGS_TEXT + "# " + "x" * 8000 + "\n"
        dist = site.add_runtime("32", padded)
    assert host_facts.read_runtime_flags(dist) is None


def test_a_listed_file_that_is_gone_from_disk_reads_as_none(tmp_path):
    dist = _dist(tmp_path, DEFAULT_FLAGS_TEXT)
    listed = [
        entry for entry in dist.files or () if entry.name == "build_feature_flags.py"
    ]
    assert len(listed) == 1
    dist.locate_file(listed[0]).unlink()
    assert host_facts.read_runtime_flags(dist) is None


@pytest.mark.parametrize(
    ("token", "flags", "expected"),
    [
        ("runtime-32", DEFAULT_SET, True),
        ("runtime-64", DEFAULT_SET, True),
        ("compat", COMPAT_SET, True),
        ("runtime-32", tuple(reversed(DEFAULT_SET)), True),
        ("runtime-32", DEFAULT_SET[:-1], False),
        ("runtime-32", (*DEFAULT_SET, "avx512f"), False),
        ("compat", DEFAULT_SET, False),
        ("runtime-32", COMPAT_SET, False),
        ("runtime-32", None, False),
        ("absent", DEFAULT_SET, False),
        (UNKNOWN, DEFAULT_SET, False),
    ],
)
def test_a_runtimes_flags_match_its_declared_set_as_sets(token, flags, expected):
    assert host_facts.runtime_flags_match(token, flags) is expected


# --------------------------------------------------------------------------------------
# The drift test: the locked runtime against the declared set
# --------------------------------------------------------------------------------------


def runtime_drift(
    distribution: Any,
    token: str,
    *,
    declared: Optional[tuple[str, ...]] = None,
    names: Optional[Mapping[str, Any]] = None,
) -> list[str]:
    """What differs between a runtime's installed flags file and the reader's declaration.

    ``declared`` and ``names`` default to the module's own declared set for ``token`` and
    its name table; a control passes others to show a check firing on its own.
    """
    flags = host_facts.read_runtime_flags(distribution)
    if flags is None:
        return [
            (
                "the flags file is not where the reader looks: not in the distribution's "
                "file list, not readable, or not an assignment of BUILD_FEATURE_FLAGS"
            )
        ]
    installed = set(flags)
    expected = set(RUNTIME_FLAGS[token] if declared is None else declared)
    problems = []
    if installed - expected:
        problems.append(
            f"the runtime requires flags the reader does not declare for {token}: "
            f"{sorted(installed - expected)}"
        )
    if expected - installed:
        problems.append(
            f"the reader declares flags the runtime no longer requires for {token}: "
            f"{sorted(expected - installed)}"
        )
    unnamed = installed - set(FLAG_SPELLINGS if names is None else names)
    if unnamed:
        problems.append(f"flags with no spelling in the name table: {sorted(unnamed)}")
    return problems


def _flags_file_text(distribution: Any) -> str:
    for entry in distribution.files or ():
        if entry.name == "build_feature_flags.py":
            return distribution.locate_file(entry).read_text(encoding="utf-8")
    raise AssertionError("the installed runtime lists no build_feature_flags.py")


def _locked_version(name: str) -> str:
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    versions = [
        package["version"] for package in lock["package"] if package["name"] == name
    ]
    assert len(versions) == 1, f"uv.lock holds {len(versions)} entries for {name}"
    return versions[0]


def _installed(name: str) -> Optional[importlib.metadata.Distribution]:
    try:
        return importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def test_the_environment_is_the_one_the_lock_describes():
    # The drift test below measures the installed files; it says which version they are.
    for name in ("polars", "polars-runtime-32"):
        installed = _installed(name)
        assert installed is not None, f"{name} is not installed; sync the environment"
        assert installed.version == _locked_version(name), (
            f"{name} {installed.version} is installed and uv.lock has "
            f"{_locked_version(name)}: sync with uv sync --frozen"
        )


def test_the_locked_runtimes_flags_equal_the_declared_set_and_are_all_named():
    installed = _installed("polars-runtime-32")
    assert installed is not None, "polars-runtime-32 is not installed in this lane"
    assert runtime_drift(installed, "runtime-32") == []


def test_polars_still_selects_a_runtime_the_way_the_reader_mirrors():
    polars = _installed("polars")
    assert polars is not None, "polars is not installed in this lane"
    text = polars.locate_file("polars/_plr.py").read_text(encoding="utf-8")
    assert anchors_missing(text, PLR_ANCHORS) == []
    check = polars.locate_file("polars/_cpu_check.py").read_text(encoding="utf-8")
    assert anchors_missing(check, CPU_CHECK_ANCHORS) == []


#: Lines of polars' ``_plr.py`` the reader's runtime choice follows, and the lines of
#: ``_cpu_check.py`` its flag parsing follows. A polars that rewrites any of them has
#: changed the layout the reader assumes, and the lock bump that brings it fails here.
PLR_ANCHORS = (
    "default_prefer = [rt_compat, rt_64, rt_32]",
    'pkgs = {"compat": rt_compat, "64": rt_64, "32": rt_32}',
    '_force = os.environ.get("POLARS_FORCE_PKG")',
    '_prefer = os.environ.get("POLARS_PREFER_PKG")',
    "preference.insert(0, pkgs[_prefer])",
    'if hasattr(builtins, "__POLARS_PLR"):',
    "from _polars_runtime_compat import BUILD_FEATURE_FLAGS",
    "from _polars_runtime_64 import BUILD_FEATURE_FLAGS",
    "from _polars_runtime_32 import BUILD_FEATURE_FLAGS",
    "if sys.modules[__name__].__version__ != PKG_VERSION:",
)
CPU_CHECK_ANCHORS = (
    'f.lstrip("+") for f in feature_flags.split(",") if not f.startswith("-")',
    'if f and f != "ctr-static"',
    'if not expected_cpu_flags or os.environ.get("POLARS_SKIP_CPU_CHECK"):',
)


def anchors_missing(text: str, anchors: tuple[str, ...]) -> list[str]:
    return [anchor for anchor in anchors if anchor not in text]


def test_each_anchor_turns_the_check_red_when_its_line_changes():
    polars = _installed("polars")
    assert polars is not None
    text = polars.locate_file("polars/_plr.py").read_text(encoding="utf-8")
    assert anchors_missing(text, PLR_ANCHORS) == []
    for anchor in PLR_ANCHORS:
        # Every occurrence changes: polars repeats some lines (the version check).
        changed = text.replace(anchor, anchor.replace(" ", "  ", 1))
        assert changed != text, f"the control found no {anchor!r} to change"
        assert anchors_missing(changed, PLR_ANCHORS) == [anchor]


# The controls: a copy of the real file with one flag added, one removed, or unlisted.


def test_an_unchanged_copy_of_the_real_file_is_the_must_not_flag_control(tmp_path):
    installed = _installed("polars-runtime-32")
    assert installed is not None
    copy = Site(tmp_path).add_runtime("32", _flags_file_text(installed))
    assert runtime_drift(copy, "runtime-32") == []


def test_a_copy_with_one_flag_added_turns_the_drift_check_red(tmp_path):
    installed = _installed("polars-runtime-32")
    assert installed is not None
    real = _flags_file_text(installed)
    changed = real.replace('+movbe"', '+movbe,+avx512f"')
    assert changed != real, "the control found no +movbe to extend"
    problems = runtime_drift(Site(tmp_path).add_runtime("32", changed), "runtime-32")
    assert any("does not declare" in problem for problem in problems), problems
    assert any("no spelling in the name table" in problem for problem in problems), (
        problems
    )


def test_a_copy_with_one_flag_removed_turns_the_drift_check_red(tmp_path):
    installed = _installed("polars-runtime-32")
    assert installed is not None
    real = _flags_file_text(installed)
    changed = real.replace(",+movbe", "")
    assert changed != real, "the control found no +movbe to remove"
    problems = runtime_drift(Site(tmp_path).add_runtime("32", changed), "runtime-32")
    assert any("no longer requires" in problem for problem in problems), problems


def test_a_copy_whose_file_moved_turns_the_drift_check_red(tmp_path):
    installed = _installed("polars-runtime-32")
    assert installed is not None
    real = _flags_file_text(installed)
    unlisted = Site(tmp_path).add_runtime("32", real, listed=False)
    problems = runtime_drift(unlisted, "runtime-32")
    assert problems and "not where the reader looks" in problems[0]


def test_a_flag_the_name_table_lacks_is_named_even_when_the_declared_set_matches(
    tmp_path,
):
    # Declared and installed agree on a flag nobody spelled: the table check fires alone.
    text = DEFAULT_FLAGS_TEXT.replace('+movbe"', '+movbe,+avx512f"')
    dist = Site(tmp_path).add_runtime("32", text)
    problems = runtime_drift(dist, "runtime-32", declared=(*DEFAULT_SET, "avx512f"))
    assert problems == ["flags with no spelling in the name table: ['avx512f']"]


def test_a_flag_that_is_both_declared_and_spelled_is_not_drift(tmp_path):
    text = DEFAULT_FLAGS_TEXT.replace('+movbe"', '+movbe,+avx512f"')
    dist = Site(tmp_path).add_runtime("32", text)
    spelled = {**FLAG_SPELLINGS, "avx512f": FLAG_SPELLINGS["avx2"]}
    assert (
        runtime_drift(
            dist, "runtime-32", declared=(*DEFAULT_SET, "avx512f"), names=spelled
        )
        == []
    )


# The arm64 lanes. polars sets target-feature flags only for its x86-64 builds, so the
# runtime wheel an arm64 host installs carries an empty BUILD_FEATURE_FLAGS: there is
# no declared set to compare it with, and the reader answers n/a without reading it.
# The four tests above run here under a planted lane (a runtime holding the text given,
# on a host of the machine given), so every host runs the branch that is not its own.

EMPTY_FLAGS_TEXT = 'BUILD_FEATURE_FLAGS = ""\n'

DRIFT_TESTS = [
    test_the_locked_runtimes_flags_equal_the_declared_set_and_are_all_named,
    test_an_unchanged_copy_of_the_real_file_is_the_must_not_flag_control,
    test_a_copy_with_one_flag_added_turns_the_drift_check_red,
    test_a_copy_with_one_flag_removed_turns_the_drift_check_red,
]


def plant_lane(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, machine: str, flags_text: str
) -> None:
    """Install a runtime holding ``flags_text`` on a host of ``machine``."""
    runtime = Site(tmp_path).add_runtime("32", flags_text)
    real = _installed

    def installed(name: str) -> Optional[importlib.metadata.Distribution]:
        return runtime if name == "polars-runtime-32" else real(name)

    monkeypatch.setattr(sys.modules[__name__], "_installed", installed)
    monkeypatch.setattr(platform, "machine", lambda: machine)


def run_drift_test(test: Callable[..., None], tmp_path: Path) -> None:
    if "tmp_path" in inspect.signature(test).parameters:
        test(tmp_path)
    else:
        test()


@pytest.mark.parametrize("test", DRIFT_TESTS, ids=lambda test: test.__name__)
@pytest.mark.parametrize("machine", ["aarch64", "arm64"])
def test_the_drift_tests_hold_on_an_arm64_lane(monkeypatch, tmp_path, machine, test):
    plant_lane(monkeypatch, tmp_path, machine, EMPTY_FLAGS_TEXT)
    run_drift_test(test, tmp_path)


@pytest.mark.parametrize("test", DRIFT_TESTS, ids=lambda test: test.__name__)
@pytest.mark.parametrize("machine", ["x86_64", "AMD64"])
def test_the_drift_tests_hold_on_an_x86_64_lane(monkeypatch, tmp_path, machine, test):
    plant_lane(monkeypatch, tmp_path, machine, DEFAULT_FLAGS_TEXT)
    run_drift_test(test, tmp_path)


@pytest.mark.parametrize("machine", ["aarch64", "arm64"])
def test_flags_in_an_arm64_runtime_are_drift(monkeypatch, tmp_path, machine):
    # The reader never reads the file there. A polars that starts to set flags for
    # arm64 must turn the lane red, not pass as unread.
    plant_lane(monkeypatch, tmp_path, machine, DEFAULT_FLAGS_TEXT)
    with pytest.raises(AssertionError):
        test_the_locked_runtimes_flags_equal_the_declared_set_and_are_all_named()


@pytest.mark.parametrize("machine", ["x86_64", "AMD64"])
def test_an_empty_flags_file_on_x86_64_is_drift(monkeypatch, tmp_path, machine):
    plant_lane(monkeypatch, tmp_path, machine, EMPTY_FLAGS_TEXT)
    with pytest.raises(AssertionError):
        test_the_locked_runtimes_flags_equal_the_declared_set_and_are_all_named()


# The second lane, where polars[rtcompat] (or polars[rt64]) is installed. The default
# lane installs neither, so these two skip there; a lane that installs one runs its case.


@pytest.mark.parametrize(
    ("distribution", "token"),
    [
        pytest.param(
            "polars-runtime-compat",
            "compat",
            marks=pytest.mark.skipif(
                _installed("polars-runtime-compat") is None,
                reason="polars[rtcompat] is not installed in this lane",
            ),
        ),
        pytest.param(
            "polars-runtime-64",
            "runtime-64",
            marks=pytest.mark.skipif(
                _installed("polars-runtime-64") is None,
                reason="polars[rt64] is not installed in this lane",
            ),
        ),
    ],
)
def test_an_installed_optional_runtime_matches_its_declared_set(distribution, token):
    installed = _installed(distribution)
    assert installed is not None
    assert runtime_drift(installed, token) == []
