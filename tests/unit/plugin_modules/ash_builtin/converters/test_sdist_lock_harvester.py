# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sdist lockfile harvester's fetch, verify, cache and skip behavior.

Covers A7 rows 3 (hash-mismatch refusal), 4 (offline semantics, cold and warmed
cache), 7 (size cap) and the happy path that materializes a lockfile and its
provenance manifest into the converted target. The network is a counted stub on
``download_utils._open_url`` -- the one opener every ASH download goes through --
so "zero network calls" is a measured count, not an absence of evidence, and the
sha256 verification exercised is the REAL one in ``download_utils``.

Also the cache's trust boundary and the transfer bound, the fix round's rows:

- a cache entry the scanned repository ships in its own tree (committed under
  the default output directory) is never served as a verified harvest;
- a cached lockfile whose bytes no longer match the digest recorded when the
  entry was written is not served: the entry is evicted and treated as cold;
- the ``max_sdist_mb`` bound holds against the bytes actually streamed, not
  only against the lock's own (attacker-aligned) size claim.

And the path with the syft scanner disabled: which packages and lockfiles it
names, for which of grype and trivy, and what it does not set up.
"""

from __future__ import annotations

import hashlib
import io
import json
import ntpath
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    SdistLockHarvester,
)
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    sdist_lock_harvester as harvester_module,
)
from automated_security_helper.utils import download_utils
from automated_security_helper.utils.scanned_tree import TreeInputRefused
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


class CountedBody(io.BytesIO):
    """A served body that counts the bytes actually read from it.

    Counted on the object (not read back with ``tell()``) because the
    download's ``with`` block closes the response, after which ``tell()``
    raises; the count survives the close, so a test can measure whether a
    transfer was aborted (consumed < the payload) or drained whole.
    """

    def __init__(self, body: bytes):
        super().__init__(body)
        self.consumed = 0

    def read(self, *args, **kwargs) -> bytes:
        data = super().read(*args, **kwargs)
        self.consumed += len(data)
        return data


class CountingOpener:
    """Serves pinned payloads in ``download_utils._open_url``'s shape, counting."""

    def __init__(self, payloads: Dict[str, bytes]):
        self.payloads = payloads
        self.calls: List[str] = []
        #: Every response handed out, so a test can measure how much of a body
        #: was actually consumed: an aborted transfer reads less than the
        #: payload, a completed one reads it whole.
        self.responses: List[CountedBody] = []

    def __call__(self, url: str, timeout: float) -> CountedBody:
        self.calls.append(url)
        if url not in self.payloads:
            raise AssertionError(f"unexpected fetch of {url}")
        response = CountedBody(self.payloads[url])
        self.responses.append(response)
        return response


@pytest.fixture
def harvest_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A source tree with a fixture uv.lock, a context, and a counted opener.

    ``XDG_CACHE_HOME`` is pinned into the test's own directory so the user-level
    default harvest cache can never read from or write to the developer's real
    cache, and so each test starts cold.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    opener = CountingOpener({SDIST_URL: fixture_sdist_bytes()})
    monkeypatch.setattr(download_utils, "_open_url", opener)

    def build(
        lock_bytes: bytes | None = None, config=None, output_dir: Path | None = None
    ) -> SdistLockHarvester:
        source.joinpath("uv.lock").write_bytes(
            fixture_uv_lock(SDIST_URL, WHEEL_URL) if lock_bytes is None else lock_bytes
        )
        context = PluginContext(
            source_dir=source,
            output_dir=output if output_dir is None else output_dir,
            config=get_default_config() if config is None else config,
        )
        return SdistLockHarvester(context=context)

    return source, output, opener, build


def _harvest_dir(converter: SdistLockHarvester) -> Path:
    return converter.results_dir.joinpath(HARVEST_DIR_NAME, "fixturepkg", "0.1.0")


def test_harvest_materializes_lockfile_and_manifest(
    harvest_env, tmp_path: Path
) -> None:
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
    # The verified harvest is cached at the user-level cache root, keyed by the
    # pin, beside the digest every later read re-verifies -- and never under the
    # scan's output directory, which the default layout puts in the scanned tree.
    cache_entry = (
        tmp_path / "xdg-cache" / "ash" / "sdist-harvest" / manifest["sdist_sha256"]
    )
    assert cache_entry.joinpath("Cargo.lock").is_file()
    index = json.loads(
        cache_entry.joinpath("cached-lockfiles.json").read_text(encoding="utf-8")
    )
    assert index["digests"]["Cargo.lock"] == (
        hashlib.sha256(cache_entry.joinpath("Cargo.lock").read_bytes()).hexdigest()
    )
    assert not output.joinpath("sdist-harvest").exists()
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


def test_hash_mismatch_refuses_the_bytes_before_any_extraction(
    harvest_env, tmp_path: Path
) -> None:
    _source, output, opener, build = harvest_env
    honest = fixture_sdist_bytes()
    tampered = bytes([honest[0] ^ 0x01]) + honest[1:]
    opener.payloads[SDIST_URL] = tampered
    # The lock pins the HONEST digest; the server serves tampered bytes.
    converter = build(lock_bytes=fixture_uv_lock(SDIST_URL, WHEEL_URL))

    results = converter.convert()

    assert results == []
    assert not _harvest_dir(converter).exists(), "nothing may be extracted"
    for cache_root in (output.joinpath("sdist-harvest"), tmp_path / "xdg-cache"):
        assert not list(cache_root.glob("**/cached-lockfiles.json")), (
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


def test_syft_disabled_skips_every_flagged_package_visibly(harvest_env) -> None:
    """With syft off nothing is fetched, and the skip is one visible record.

    Grype and trivy read the harvested lockfiles, so the converter says which
    packages it did not harvest instead of returning silently. The record is a
    skip, not a failure, so it carries no limit and does not fail the gate.
    """
    _source, _output, opener, build = harvest_env
    config = get_default_config()
    config.scanners.syft.enabled = False
    converter = build(config=config)

    assert converter.convert() == []
    assert opener.calls == []
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "scanners.syft.enabled" in record.reason
    assert "fixturepkg 0.1.0" in record.reason
    assert "purepkg" not in record.reason
    assert record.limit is None
    assert converter.failed_inputs == []


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


def test_lockfile_is_found_in_a_windows_shaped_scan_set(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scan-set paths built with ``os.path.join`` carry backslashes on Windows.

    The basename match must hold on every platform, so the paths here are
    built with ``ntpath.join`` and fed through the same converter code path.
    """
    _source, _output, _opener, build = harvest_env
    converter = build()
    windows_lock = ntpath.join("C:\\", "work", "repo", "sub", "uv.lock")
    windows_other = ntpath.join("C:\\", "work", "repo", "sub", "notes.txt")
    monkeypatch.setattr(
        harvester_module,
        "scan_set",
        lambda **_kwargs: [windows_lock, windows_other],
    )

    assert converter._lockfiles_in_scan_set(["uv.lock"]) == [windows_lock]


def test_tree_shipped_cache_entry_is_never_served(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cache entry committed INSIDE the scanned tree is ignored.

    The default layout puts the output directory in the scanned tree
    (``.ash/ash_output``), and a persistent cache there is neither wiped at scan
    start nor covered by the committed-output refusal: a repository could commit
    a pre-warmed entry, self-consistent digests included, and have its own bytes
    served to every scanner as a VERIFIED harvest, provenance stamps and all.
    The run must treat such a package as a cold miss instead.
    """
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    source, _output, opener, build = harvest_env
    in_tree_output = source / ".ash" / "ash_output"
    pin = hashlib.sha256(fixture_sdist_bytes()).hexdigest()
    poison = b'[[package]]\nname = "poisoned-crate"\nversion = "6.6.6"\n'
    entry = in_tree_output / "sdist-harvest" / pin
    entry.mkdir(parents=True)
    entry.joinpath("Cargo.lock").write_bytes(poison)
    entry.joinpath("cached-lockfiles.json").write_text(
        json.dumps(
            {
                "sha256": pin,
                "lockfiles": ["Cargo.lock"],
                # Self-consistent on purpose: PLACEMENT, not the digest record,
                # is what must keep tree-shipped bytes out of the harvest.
                "digests": {"Cargo.lock": hashlib.sha256(poison).hexdigest()},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    converter = build(output_dir=in_tree_output)

    results = converter.convert()

    assert results == [], "tree-shipped cache bytes must never be materialized"
    assert opener.calls == []
    assert not _harvest_dir(converter).exists()
    assert not [
        path
        for path in converter.results_dir.glob("**/*")
        if path.is_file() and poison in path.read_bytes()
    ], "the poisoned bytes must not reach the converted target anywhere"
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "offline" in record.reason, "a cold miss offline is a visible skip"


def test_tampered_cache_bytes_are_evicted_not_served(
    harvest_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cached lockfile that no longer matches its recorded digest is not served.

    The cache key (the sdist's sha256 pin) authorizes an entry; the digests
    recorded when the entry was written are what tie the served BYTES to that
    key. Bytes that match no recorded digest are evicted with the entry and the
    package is a cold miss, never a verified harvest.
    """
    _source, output, opener, build = harvest_env
    build().convert()
    assert len(opener.calls) == 1

    # Wherever the cache root is, exactly one entry was warmed.
    roots = [output, tmp_path / "xdg-cache"]
    (index,) = [p for root in roots for p in root.glob("**/cached-lockfiles.json")]
    entry = index.parent
    tampered = b'[[package]]\nname = "tampered-crate"\nversion = "6.6.6"\n'
    entry.joinpath("Cargo.lock").write_bytes(tampered)

    monkeypatch.setenv("ASH_OFFLINE", "YES")
    converter = build()
    results = converter.convert()

    assert results == [], "tampered cache bytes must not be materialized"
    served = _harvest_dir(converter).joinpath("Cargo.lock")
    assert not served.exists() or tampered not in served.read_bytes()
    assert not entry.exists(), "an unverifiable entry must be evicted"
    assert len(opener.calls) == 1, "offline: the eviction must not fetch"
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "offline" in record.reason


def test_oversize_stream_is_aborted_at_the_cap(harvest_env, tmp_path: Path) -> None:
    """``max_sdist_mb`` holds against the bytes actually streamed.

    The lock's own size claim is the scanned repository's claim, so a lying
    small claim must not buy an unbounded transfer: the fetch is aborted ON THE
    WIRE once the bound passes, nothing is extracted, and the skip names the
    option. The sha256 pin here really is the big body's digest, so without the
    bound the transfer would verify and harvest end to end.
    """
    import random

    _source, output, opener, build = harvest_env
    # Incompressible filler, so the served archive really is ~5 MiB on the wire.
    blob = random.Random(1337).randbytes(5 * 1024 * 1024)
    oversized = fixture_sdist_bytes(extra_members={"fixturepkg-0.1.0/filler.bin": blob})
    assert len(oversized) > 4 * 1024 * 1024
    opener.payloads[SDIST_URL] = oversized
    config = get_default_config()
    config.scanners.syft.options.sdist_harvest.max_sdist_mb = 1
    converter = build(
        lock_bytes=fixture_uv_lock(
            SDIST_URL, WHEEL_URL, sdist_bytes=oversized, sdist_size=1000
        ),
        config=config,
    )

    results = converter.convert()

    assert results == [], "a transfer past max_sdist_mb must never be harvested"
    assert not _harvest_dir(converter).exists()
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "max_sdist_mb" in record.reason
    (response,) = opener.responses
    assert response.consumed < len(oversized), (
        "the transfer must be ABORTED at the bound, not completed and discarded"
    )
    roots = [output, tmp_path / "xdg-cache"]
    assert not [p for root in roots for p in root.glob("**/cached-lockfiles.json")], (
        "a refused transfer must cache nothing"
    )


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("name", "../x"),
        ("name", ".hidden"),
        ("name", "a/b"),
        ("version", "../../escape"),
        ("version", "1.0/../x"),
    ],
)
def test_identifier_that_is_not_a_package_identifier_is_skipped(
    harvest_env, field: str, bad_value: str
) -> None:
    """A lock's name/version names a directory under the results dir; a value
    with a path separator or a leading dot is rejected at parse time, never
    fetched and never joined into a path."""
    _source, output, opener, build = harvest_env
    lock = fixture_uv_lock(SDIST_URL, WHEEL_URL)
    original = b'name = "fixturepkg"' if field == "name" else b'version = "0.1.0"'
    replaced = f'{field} = "{bad_value}"'.encode()
    assert original in lock
    lock = lock.replace(original, replaced, 1)
    converter = build(lock_bytes=lock)

    results = converter.convert()

    assert results == []
    assert opener.calls == [], "a rejected entry must authorize no fetch"
    assert not list(output.glob("**/Cargo.lock"))
    assert not list(output.parent.glob("**/x/**/Cargo.lock"))
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "not a valid package" in record.reason


@pytest.mark.parametrize("digest", ["z" * 64, "g" * 63 + "0", "-" * 64])
def test_sha256_pin_that_is_not_hex_is_skipped(harvest_env, digest: str) -> None:
    _source, _output, opener, build = harvest_env
    converter = build(
        lock_bytes=fixture_uv_lock(SDIST_URL, WHEEL_URL, sdist_sha256=digest)
    )

    results = converter.convert()

    assert results == []
    assert opener.calls == [], "a non-hex pin must authorize no fetch"
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "not a 64-character hex digest" in record.reason


def test_confined_path_refuses_an_up_level_join_and_accepts_a_normal_one(
    tmp_path: Path,
) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.converters.sdist_lock_harvester import (
        confined_path,
    )

    root = tmp_path / "root"
    root.mkdir()
    assert confined_path(root, "pkg", "1.0") == (root / "pkg" / "1.0").resolve()
    assert confined_path(root, "..", "x") is None
    assert confined_path(root, "pkg", "..", "..", "x") is None
    assert confined_path(root, "/etc") is None
    assert confined_path(root) is None, "the root itself is not an entry under it"


def test_confined_path_refuses_a_symlink_that_leaves_the_root(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.converters.sdist_lock_harvester import (
        confined_path,
    )

    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    root.joinpath("link").symlink_to(outside, target_is_directory=True)

    assert confined_path(root, "link", "x") is None


def test_eviction_never_removes_a_directory_outside_the_cache_root(
    harvest_env, tmp_path: Path
) -> None:
    _source, _output, _opener, build = harvest_env
    converter = build()
    cache_root = tmp_path / "cache"
    cache_root.mkdir()
    outside = tmp_path / "precious"
    outside.mkdir()
    outside.joinpath("keep.txt").write_text("keep")
    inside = cache_root / ("a" * 64)
    inside.mkdir()

    assert converter._evict_cache_entry(cache_root, outside, "test") is None
    assert converter._evict_cache_entry(cache_root, inside, "test") is None

    assert outside.joinpath("keep.txt").is_file(), "never rmtree outside the root"
    assert not inside.exists(), "an entry under the root is still evicted"


def test_cache_index_is_written_atomically(
    harvest_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cache index replaces its file whole, so a reader never sees a torn one.

    A plain ``write_text`` truncates the index before writing it; a concurrent
    scan that reads the entry in that window finds a file that exists but does
    not parse, evicts the entry and re-fetches. The index goes through the
    repo's own ``write_text_atomically``, and a complete, parseable index is the
    only thing a reader can find.
    """
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        sdist_lock_harvester,
    )
    from automated_security_helper.utils import atomic_write

    written: List[Path] = []
    real = atomic_write.write_text_atomically

    def spy(path: Path, content: str, *args, **kwargs) -> None:
        written.append(Path(path))
        real(path, content, *args, **kwargs)

    monkeypatch.setattr(sdist_lock_harvester, "write_text_atomically", spy)
    _source, _output, _opener, build = harvest_env

    build().convert()

    # The harvest manifest goes through the same writer; the index is written once.
    index = [p for p in written if p.name == "cached-lockfiles.json"]
    assert len(index) == 1
    assert sorted(p.name for p in written) == [
        "cached-lockfiles.json",
        "harvest-manifest.json",
    ]
    assert json.loads(index[0].read_text(encoding="utf-8"))["lockfiles"] == [
        "Cargo.lock"
    ]


# ----------------------------------------------------------------------
# With syft off: what is named, for whom, and what is left alone
# ----------------------------------------------------------------------
#
# With the syft scanner disabled nothing is fetched. grype and trivy still read
# the harvested lockfiles, so for each of them that runs the converter names the
# packages it did not harvest, and with neither running it has nothing to say.

#: A refusal reason no real check writes, so a test can tell its record apart.
PLANTED_REFUSAL = "a refusal planted by the test"

#: Bytes that are not a TOML document: a bare key may not hold a space.
NOT_TOML = b"this is = [not toml\n"


def _syft_off_config(*readers_on: str):
    """A default config with syft off and only ``readers_on`` of grype and trivy on."""
    config = get_default_config()
    config.scanners.syft.enabled = False
    for reader in ("grype", "trivy"):
        getattr(config.scanners, reader).enabled = reader in readers_on
    return config


def _refuse_every_open(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every lockfile the converter opens a refused tree input."""

    def refuse(self, path):
        raise TreeInputRefused(path="uv.lock", reason=PLANTED_REFUSAL)

    monkeypatch.setattr(SdistLockHarvester, "open_source_file", refuse)


def test_with_syft_grype_and_trivy_off_the_tree_is_not_walked(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With syft, grype and trivy all off, nothing reads a harvest.

    The converter returns before the scan-set walk and writes no record, so a
    setup that runs none of them gets no record whose claim does not apply to it.
    """
    _source, _output, opener, build = harvest_env
    converter = build(config=_syft_off_config())
    walked: List[List[str]] = []
    real = SdistLockHarvester._lockfiles_in_scan_set

    def spy(self, names):
        walked.append(list(names))
        return real(self, names)

    monkeypatch.setattr(SdistLockHarvester, "_lockfiles_in_scan_set", spy)

    assert converter.convert() == []
    assert walked == [], "nothing reads a harvest, so the tree is not walked"
    assert converter.refused_inputs == []
    assert converter.failed_inputs == []
    assert opener.calls == []


@pytest.mark.parametrize("on", ["grype", "trivy"])
def test_with_syft_off_the_record_names_only_the_readers_that_run(
    harvest_env, on: str
) -> None:
    """The record says whose input misses the packages: the reader that runs only."""
    _source, _output, opener, build = harvest_env
    off = "trivy" if on == "grype" else "grype"
    converter = build(config=_syft_off_config(on))

    assert converter.convert() == []
    assert opener.calls == []
    (record,) = converter.refused_inputs
    assert f"missing from the input of {on}" in record.reason
    assert off not in record.reason
    assert "fixturepkg 0.1.0" in record.reason


def test_with_syft_off_and_both_readers_on_the_record_names_both(harvest_env) -> None:
    _source, _output, _opener, build = harvest_env
    converter = build(config=_syft_off_config("grype", "trivy"))

    assert converter.convert() == []
    (record,) = converter.refused_inputs
    assert "missing from the input of grype and trivy" in record.reason
    assert record.limit is None


def test_with_syft_off_the_record_does_not_speak_of_an_sbom(harvest_env) -> None:
    """syft makes the SBOM, so with syft off there is none for the record to name.

    It names the packages that were not harvested instead.
    """
    _source, _output, _opener, build = harvest_env
    converter = build(config=_syft_off_config("grype", "trivy"))

    converter.convert()
    (record,) = converter.refused_inputs
    assert "SBOM" not in record.reason
    assert "not harvested: fixturepkg 0.1.0" in record.reason


def test_with_syft_off_a_rejected_entry_keeps_its_own_cause(harvest_env) -> None:
    """An entry the lock parse rejected would not be fetched with syft on either.

    Its record says why, not that syft is off.
    """
    _source, _output, opener, build = harvest_env
    converter = build(
        lock_bytes=fixture_uv_lock(SDIST_URL, WHEEL_URL, sdist_sha256="z" * 64),
        config=_syft_off_config("grype", "trivy"),
    )

    assert converter.convert() == []
    assert opener.calls == []
    (record,) = converter.refused_inputs
    assert "not a 64-character hex digest" in record.reason
    assert "scanners.syft.enabled" not in record.reason


def test_with_syft_off_an_entry_with_no_sha256_pin_keeps_its_own_cause(
    harvest_env,
) -> None:
    """An entry that pins no sdist by sha256 authorizes no fetch whatever syft says."""
    _source, _output, opener, build = harvest_env
    lock = fixture_uv_lock(SDIST_URL, WHEEL_URL)
    pinned = f'sdist = {{ url = "{SDIST_URL}", hash = "sha256:'.encode()
    assert lock.count(pinned) == 1
    lock = lock.replace(
        pinned, f'sdist = {{ url = "{SDIST_URL}", hash = "md5:'.encode()
    )
    converter = build(lock_bytes=lock, config=_syft_off_config("grype", "trivy"))

    assert converter.convert() == []
    assert opener.calls == []
    (record,) = converter.refused_inputs
    assert "pins no sdist by sha256" in record.reason
    assert "scanners.syft.enabled" not in record.reason


def test_with_syft_off_a_refused_lockfile_is_still_named(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lockfile the tree refuses cannot name its packages, so it is named itself.

    The record is the one syft on writes: the tree's refusal, with no limit.
    """
    _source, _output, _opener, build = harvest_env
    converter = build(config=_syft_off_config("grype", "trivy"))
    _refuse_every_open(monkeypatch)

    assert converter.convert() == []
    (record,) = converter.refused_inputs
    assert record.path == "uv.lock"
    assert PLANTED_REFUSAL in record.reason
    assert record.limit is None
    assert converter.failed_inputs == []


def test_with_syft_off_a_lockfile_that_does_not_parse_is_named_and_fails_nothing(
    harvest_env,
) -> None:
    """With syft off nothing would have been fetched from it, so it fails no gate.

    It is named in a skip record with no limit, not recorded as a failed input.
    """
    _source, _output, opener, build = harvest_env
    converter = build(lock_bytes=NOT_TOML, config=_syft_off_config("grype", "trivy"))

    assert converter.convert() == []
    assert opener.calls == []
    assert converter.failed_inputs == []
    (record,) = converter.refused_inputs
    assert HARVEST_SKIPPED_RULE in record.reason
    assert "not a TOML document" in record.reason
    assert "scanners.syft.enabled" in record.reason
    assert record.limit is None


def test_control_with_syft_on_a_lockfile_that_does_not_parse_is_a_failed_input(
    harvest_env,
) -> None:
    """With syft on the harvest set out to read the lockfile, so it is lost coverage."""
    _source, _output, opener, build = harvest_env
    converter = build(lock_bytes=NOT_TOML)

    assert converter.convert() == []
    assert opener.calls == []
    (failed,) = converter.failed_inputs
    assert "not a TOML document" in failed.reason
    assert converter.refused_inputs == []


def test_control_with_syft_on_a_refused_lockfile_is_a_refused_input(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source, _output, opener, build = harvest_env
    converter = build()
    _refuse_every_open(monkeypatch)

    assert converter.convert() == []
    assert opener.calls == []
    (record,) = converter.refused_inputs
    assert PLANTED_REFUSAL in record.reason
    assert converter.failed_inputs == []


def test_candidate_input_count_with_syft_off_counts_what_the_harvest_walks(
    harvest_env,
) -> None:
    """With syft off and a reader on, convert() still walks the lockfiles to name
    what it does not fetch, so the count is the one syft on gives."""
    _source, _output, _opener, build = harvest_env
    converter = build(config=_syft_off_config("grype", "trivy"))

    assert converter.candidate_input_count() == 1


def test_candidate_input_count_with_syft_grype_and_trivy_off_is_zero(
    harvest_env,
) -> None:
    _source, _output, _opener, build = harvest_env
    converter = build(config=_syft_off_config())

    assert converter.candidate_input_count() == 0


def test_with_syft_off_no_cache_no_staging_and_no_results_dir_are_made(
    harvest_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With syft off nothing is fetched, so nothing is set up for a fetch.

    No cache root is asked for (its checks can warn), no per-run staging
    directory is made and no results directory is created. The packages are
    still named, which shows the syft-off path ran.
    """
    _source, _output, _opener, build = harvest_env
    converter = build(config=_syft_off_config("grype", "trivy"))
    asked: List[object] = []
    made: List[object] = []
    real_temporary_directory = harvester_module.tempfile.TemporaryDirectory

    def cache_root_spy(self, configured):
        asked.append(configured)
        return None

    def staging_spy(*args, **kwargs):
        made.append(kwargs.get("prefix"))
        return real_temporary_directory(*args, **kwargs)

    monkeypatch.setattr(SdistLockHarvester, "_cache_root", cache_root_spy)
    monkeypatch.setattr(harvester_module.tempfile, "TemporaryDirectory", staging_spy)

    assert converter.convert() == []
    assert asked == [], "no cache root is asked for"
    assert made == [], "no staging directory is made"
    assert not converter.results_dir.exists()
    assert len(converter.refused_inputs) == 1
