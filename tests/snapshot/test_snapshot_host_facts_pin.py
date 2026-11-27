"""A snapshot reads the reference host's facts on whatever machine runs it.

``tests/snapshot/conftest.py`` pins ``platform.system()`` and ``platform.machine()`` to
linux-amd64, but the host-facts reader does not go through them. It reads the
processor's flags, the C library, the install channel and the rest from the machine
itself, so a snapshot of anything that reports the host's support would show whether
the runner has AVX2. The ``_pinned_host_facts`` fixture makes the reader's live read
answer with ``REFERENCE_FACTS``, the host the support register treats as ASH's CI
baseline.

The first test plants a host with no AVX2 as this process's own host and holds the
fixture to the reference facts. The second is its control: with the pin removed, the
same plant reads as planted, so the first cannot pass because the plant did nothing.
The third is the other half of the rule: a read that names its own sources describes a
host, and reads what it describes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.support_register import REFERENCE_FACTS
from automated_security_helper.utils import host_facts
from automated_security_helper.utils.host_facts import Sources
from tests.unit.utils.test_host_facts import SKYLAKE_FLAGS, cpuinfo, linux_host

pytestmark = pytest.mark.unit

#: The reader as the suite found it, taken when this file is imported, before any
#: fixture has pinned it.
REAL_READ_HOST_FACTS = host_facts.read_host_facts

#: An AVX2-class part with AVX2 taken away: polars' default runtime cannot run on it.
NO_AVX2_FLAGS = " ".join(flag for flag in SKYLAKE_FLAGS.split() if flag != "avx2")

REFERENCE_TOKENS = {
    name: getattr(REFERENCE_FACTS, name) for name in host_facts.FACT_FIELDS
}


def _no_avx2_host(root: Path) -> Sources:
    return linux_host(root, cpuinfo_text=cpuinfo(NO_AVX2_FLAGS))


def _as_this_process(monkeypatch: pytest.MonkeyPatch, sources: Sources) -> None:
    """Make ``sources`` what the process-wide reader reads, as the live host would be."""
    monkeypatch.setattr(host_facts, "_PROCESS_READER", None)
    monkeypatch.setattr(host_facts, "Sources", lambda: sources)


def test_a_host_with_no_avx2_reads_as_the_reference_host_under_the_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _as_this_process(monkeypatch, _no_avx2_host(tmp_path))
    reading = host_facts.read_host_facts(express_supported=lambda: True)
    assert host_facts.fact_tokens(reading) == REFERENCE_TOKENS
    assert (reading.cpu_level, reading.cpu_missing_flags) == ("full", ())


def test_the_same_host_reads_as_planted_once_the_pin_is_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _as_this_process(monkeypatch, _no_avx2_host(tmp_path))
    monkeypatch.setattr(host_facts, "read_host_facts", REAL_READ_HOST_FACTS)
    reading = host_facts.read_host_facts(express_supported=lambda: True)
    assert (reading.cpu_level, reading.cpu_missing_flags) == ("compat-only", ("avx2",))
    assert host_facts.fact_tokens(reading) != REFERENCE_TOKENS


def test_a_read_that_names_its_sources_describes_a_host_and_is_not_pinned(
    tmp_path: Path,
) -> None:
    reading = host_facts.read_host_facts(
        _no_avx2_host(tmp_path), express_supported=lambda: True
    )
    assert (reading.cpu_level, reading.cpu_missing_flags) == ("compat-only", ("avx2",))
