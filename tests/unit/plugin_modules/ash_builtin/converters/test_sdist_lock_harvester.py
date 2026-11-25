# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sdist lockfile harvester's fetch, verify, cache and skip behavior.

Covers A7 rows 3 (hash-mismatch refusal), 4 (offline semantics, cold and warmed
cache), 7 (size cap) and the happy path that materializes a lockfile and its
provenance manifest into the converted target. The network is a counted stub on
``download_utils._open_url`` -- the one opener every ASH download goes through --
so "zero network calls" is a measured count, not an absence of evidence, and the
sha256 verification exercised is the REAL one in ``download_utils``.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    SdistLockHarvester,
)
from automated_security_helper.utils import download_utils
from automated_security_helper.utils.sdist_harvest import (
    HARVEST_DIR_NAME,
    HARVEST_MANIFEST_NAME,
    HARVEST_SKIPPED_RULE,
)
from tests.utils.sdist_fixture import (
    FIXTURE_SDIST_NAME,
    FIXTURE_WHEEL_NAME,
    fixture_sdist_bytes,
    fixture_uv_lock,
)

SDIST_URL = f"https://files.test.invalid/{FIXTURE_SDIST_NAME}"
WHEEL_URL = f"https://files.test.invalid/{FIXTURE_WHEEL_NAME}"

pytestmark = pytest.mark.unit


class CountingOpener:
    """Serves pinned payloads in ``download_utils._open_url``'s shape, counting."""

    def __init__(self, payloads: Dict[str, bytes]):
        self.payloads = payloads
        self.calls: List[str] = []

    def __call__(self, url: str, timeout: float) -> io.BytesIO:
        self.calls.append(url)
        if url not in self.payloads:
            raise AssertionError(f"unexpected fetch of {url}")
        return io.BytesIO(self.payloads[url])


@pytest.fixture
def harvest_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A source tree with a fixture uv.lock, a context, and a counted opener."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    opener = CountingOpener({SDIST_URL: fixture_sdist_bytes()})
    monkeypatch.setattr(download_utils, "_open_url", opener)

    def build(lock_bytes: bytes | None = None, config=None) -> SdistLockHarvester:
        source.joinpath("uv.lock").write_bytes(
            fixture_uv_lock(SDIST_URL, WHEEL_URL) if lock_bytes is None else lock_bytes
        )
        context = PluginContext(
            source_dir=source,
            output_dir=output,
            config=get_default_config() if config is None else config,
        )
        return SdistLockHarvester(context=context)

    return source, output, opener, build


def _harvest_dir(converter: SdistLockHarvester) -> Path:
    return converter.results_dir.joinpath(HARVEST_DIR_NAME, "fixturepkg", "0.1.0")


def test_harvest_materializes_lockfile_and_manifest(harvest_env) -> None:
    _source, output, opener, build = harvest_env
    converter = build()

    results = converter.convert()

    destination = _harvest_dir(converter)
    assert destination.joinpath("Cargo.lock").is_file()
    manifest = json.loads(
        destination.joinpath(HARVEST_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert manifest["package"] == "fixturepkg"
    assert manifest["version"] == "0.1.0"
    assert manifest["parent_purl"] == "pkg:pypi/fixturepkg@0.1.0"
    assert manifest["sdist_url"] == SDIST_URL
    assert len(manifest["sdist_sha256"]) == 64
    assert manifest["lockfiles"] == ["Cargo.lock"]
    assert sorted(p.name for p in results) == ["Cargo.lock", HARVEST_MANIFEST_NAME]
    # One fetch for the one flagged package; the pure-Python entry fetched nothing.
    assert opener.calls == [SDIST_URL]
    # The verified harvest is cached under the scan workspace, keyed by the pin.
    cache_entry = output.joinpath("sdist-harvest", manifest["sdist_sha256"])
    assert cache_entry.joinpath("Cargo.lock").is_file()
    assert converter.failed_inputs == [] and converter.refused_inputs == []


def test_warmed_cache_serves_offline_with_zero_network(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source, _output, opener, build = harvest_env
    build().convert()
    assert len(opener.calls) == 1

    monkeypatch.setenv("ASH_OFFLINE", "YES")
    offline_converter = build()
    results = offline_converter.convert()

    assert len(opener.calls) == 1, "a warmed cache must serve without network"
    assert _harvest_dir(offline_converter).joinpath("Cargo.lock").is_file()
    assert [p.name for p in results].count("Cargo.lock") == 1
    assert offline_converter.refused_inputs == []


def test_offline_cold_cache_skips_with_one_visible_record(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    _source, _output, opener, build = harvest_env
    converter = build()

    results = converter.convert()

    assert results == []
    assert opener.calls == [], "offline must construct no fetch at all"
    assert not _harvest_dir(converter).exists()
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "offline" in record.reason
    assert "fixturepkg 0.1.0" in record.reason
    assert "purepkg" not in record.reason


def test_hash_mismatch_refuses_the_bytes_before_any_extraction(harvest_env) -> None:
    _source, output, opener, build = harvest_env
    honest = fixture_sdist_bytes()
    tampered = bytes([honest[0] ^ 0x01]) + honest[1:]
    opener.payloads[SDIST_URL] = tampered
    # The lock pins the HONEST digest; the server serves tampered bytes.
    converter = build(lock_bytes=fixture_uv_lock(SDIST_URL, WHEEL_URL))

    results = converter.convert()

    assert results == []
    assert not _harvest_dir(converter).exists(), "nothing may be extracted"
    cache_root = output.joinpath("sdist-harvest")
    assert not list(cache_root.glob("*/cached-lockfiles.json")), (
        "a refused fetch must cache nothing"
    )
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "did not match the lock's sha256 pin" in record.reason
    assert "fixturepkg 0.1.0" in record.reason


def test_oversize_sdist_is_skipped_before_any_fetch(harvest_env) -> None:
    _source, _output, opener, build = harvest_env
    config = get_default_config()
    config.scanners.syft.options.sdist_harvest.max_sdist_mb = 1
    converter = build(
        lock_bytes=fixture_uv_lock(SDIST_URL, WHEEL_URL, sdist_size=2 * 1024 * 1024),
        config=config,
    )

    results = converter.convert()

    assert results == []
    assert opener.calls == [], "the size bound must refuse before fetching"
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "max_sdist_mb" in record.reason


def test_disabled_option_harvests_nothing(harvest_env) -> None:
    _source, _output, opener, build = harvest_env
    config = get_default_config()
    config.scanners.syft.options.sdist_harvest.enabled = False
    converter = build(config=config)

    assert converter.convert() == []
    assert opener.calls == []
    assert converter.refused_inputs == []


def test_sdist_with_no_recognized_lockfile_is_a_visible_skip(harvest_env) -> None:
    from tests.utils.sdist_fixture import PKG_INFO

    import gzip
    import io as io_module
    import tarfile

    tar_buffer = io_module.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        info = tarfile.TarInfo(name="bare-0.1.0/PKG-INFO")
        content = PKG_INFO.encode("utf-8")
        info.size = len(content)
        archive.addfile(info, io_module.BytesIO(content))
    compressed = io_module.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as gz:
        gz.write(tar_buffer.getvalue())
    bare = compressed.getvalue()

    _source, _output, opener, build = harvest_env
    opener.payloads[SDIST_URL] = bare
    converter = build(
        lock_bytes=fixture_uv_lock(SDIST_URL, WHEEL_URL, sdist_bytes=bare)
    )

    results = converter.convert()

    assert results == []
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "no recognized embedded lockfile" in record.reason
    # The empty answer is cached too, so an offline rerun skips without network.
    assert len(opener.calls) == 1


def test_candidate_input_count_counts_configured_lockfiles(harvest_env) -> None:
    _source, _output, _opener, build = harvest_env
    converter = build()
    assert converter.candidate_input_count() == 1
