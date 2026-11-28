# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Autodetection and harvest of cross-toolchain lockfiles embedded in sdists.

Why this module exists
----------------------
ASH's SBOM is what syft reads from the scanned tree. A resolved Python dependency
that statically links another toolchain's packages is invisible to it: the polars
runtime wheel's shared library carries no cargo-auditable ``.dep-v0`` section, so
syft and trivy read zero cargo packages from the installed artifact, while the
hash-pinned sdist the project's own ``uv.lock`` resolves ships the upstream
workspace ``Cargo.lock`` at its root, and syft over that file reads the whole
crate tree. Artifacts that DO carry audit data (cargo-auditable binaries, Go
buildinfo) are already read by syft's own catalogers in its ordinary pass;
nothing here runs for them. Where both paths report a package, the SBOM merge
keys a component by its ``bom-ref``, and syft's cargo refs end in a package-id
hash that differs between runs, so the two reports name one crate under two
refs. The merge folds a harvest-stamped component onto the one already listed
with its ``purl`` (``utils/sbom_merge.py``) and redirects its dependency refs.

This module holds the pieces shared by the two halves of the feature:

* detection and harvest primitives, used by the ``sdist-lock-harvester``
  converter (``plugin_modules/ash_builtin/converters/sdist_lock_harvester.py``),
  which walks the tree's ``uv.lock`` files, flags every resolved package whose
  wheels carry a platform tag (compiled native extensions), fetches the
  HASH-PINNED sdist in online mode, verifies the pin before anything is
  extracted, and materializes only the recognized embedded lockfiles into the
  converted target, where every scanner already reads;
* provenance stamping, used by the syft scanner, which marks each SBOM component
  located under a harvest directory with CycloneDX properties naming the sdist
  digest, the parent package purl and the source URL, so every harvested
  component is auditable back to the bytes that produced it.

Nothing third-party is ever committed: the harvest extracts from the sdist the
CURRENT lockfile pins, so there is no vendored artifact to go stale.

Safety properties, stated once here and relied on by both halves:

* A fetch happens only for a URL the project's own lockfile pins by sha256, and
  ``utils.download_utils`` verifies that digest while the bytes are still in a
  temporary file -- a mismatch leaves nothing on disk and nothing is extracted.
  The transfer itself is bounded: ``max_sdist_mb`` is enforced on the streamed
  bytes (the download aborts past the bound), not only on the lock's own size
  claim, which is the scanned repository's claim.
* The harvest cache lives OUTSIDE the scanned tree (the user-level cache
  directory, :func:`default_harvest_cache_root`), every cached lockfile is
  re-verified against the digest recorded when its entry was written before it
  is served (a mismatch evicts the entry and reads as a cold miss), and a cache
  root inside the scanned tree is never used -- so a repository cannot ship a
  pre-warmed entry and have its own bytes stamped as verified provenance.
* Extraction never trusts member paths: only regular-file members whose BASE
  NAME is a recognized lockfile are read, member content is written under a path
  this module builds (never a path from the archive), and members with absolute
  or ``..`` components, links and device nodes are not read at all.
* Nothing fetched is ever executed; the harvested files are inventory evidence
  the pinned scanners parse.
"""

from __future__ import annotations

import json
import re
import tarfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Dict, List, Mapping, Optional, Sequence, Tuple

from automated_security_helper.utils.atomic_write import write_bytes_atomically
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP

if TYPE_CHECKING:  # pragma: no cover - typing only
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
        CycloneDXReport,
    )

#: The directory, under the harvester's converted output, that every harvested
#: lockfile lands in: ``sdist-locks/<package-name>/<version>/<lockfile>``. The
#: suppression entries in ``.ash.yaml`` and the provenance stamping both
#: key on this name, so it is declared once.
HARVEST_DIR_NAME = "sdist-locks"

#: The provenance record written beside each package's harvested lockfiles.
HARVEST_MANIFEST_NAME = "harvest-manifest.json"

#: The rule id a skipped harvest is reported under. A package the harvest could
#: not cover (offline with a cold cache, a refused fetch, a hash mismatch, an
#: oversize sdist, an sdist that ships no recognized lockfile) is a visible,
#: informational fact in the converter's results row, never a silent gap,
#: following the ``ash-unconverted-input`` precedent for inputs the pipeline
#: could not make scannable.
HARVEST_SKIPPED_RULE = "ash-sbom-harvest-skipped"

#: CycloneDX property names stamped onto components whose location falls under a
#: harvest directory. They ride the schema's native ``Property`` field, so
#: downstream consumers need nothing new to read them.
PROPERTY_SDIST_SHA256 = "ash:sbom-harvest:sdist-sha256"
PROPERTY_PARENT_PURL = "ash:sbom-harvest:parent-purl"
PROPERTY_SOURCE_URL = "ash:sbom-harvest:source-url"

#: Ecosystem name -> the embedded lockfile basename harvested for it. The
#: ecosystem vocabulary is the GitLab CycloneDX reporter's existing one
#: (``gitlab_cyclonedx_reporter``: ``Cargo.lock`` -> cargo, ``go.sum`` ->
#: golang, ``package-lock.json`` -> npm); the pinned syft reads each with its
#: ordinary catalogers (rust-cargo-lock, go-mod-file, javascript-lock).
ECOSYSTEM_LOCKFILES: Dict[str, str] = {
    "cargo": "Cargo.lock",
    "gomod": "go.sum",
    "npm": "package-lock.json",
}

#: The most bytes read of one embedded lockfile member. Real lockfiles are
#: hundreds of kilobytes (polars' workspace Cargo.lock is ~170 KB); the bound
#: refuses a decompression bomb wearing a lockfile's name without reading it
#: whole.
MAX_LOCKFILE_MEMBER_BYTES = 50 * 1024 * 1024


def default_harvest_cache_root() -> Optional[Path]:
    """Where verified harvests are cached when no ``cache_dir`` is configured.

    ``$XDG_CACHE_HOME/ash/sdist-harvest``, else ``~/.cache/ash/sdist-harvest``:
    the user-level placement ASH's other caches already use (the MCP source
    cache under ``~/.cache/ash-mcp``, tools under ``~/.ash/bin``), and never a
    directory the scanned repository can ship content into. The cache used to
    default to ``sdist-harvest`` under the scan's output directory, which the
    default layout puts INSIDE the scanned tree (``.ash/ash_output``): a
    repository could commit a pre-warmed entry there -- a directory that is
    neither wiped at scan start nor covered by the committed-output refusal --
    and have its own bytes served to every scanner as a verified harvest,
    provenance stamps included.

    None when there is no usable home directory and no absolute
    ``XDG_CACHE_HOME`` (``core.constants.xdg_directory``): the harvester then
    caches in a private per-run directory instead, which no repository content
    can pre-fill, at the price of no persistence between runs.
    """
    from automated_security_helper.core.constants import xdg_directory

    base = xdg_directory("XDG_CACHE_HOME", ".cache")
    if base is None:
        return None
    return base.joinpath("ash", "sdist-harvest")


#: What a lock's package name or version must look like to be used at all: the
#: harvest joins both into a directory path (``sdist-locks/<name>/<version>``)
#: and into a cache-served record, so a value a repository wrote is accepted
#: only when it is one path component of letters, digits and the PEP 503 /
#: SemVer separators ``. _ - +``, starting with a letter or digit (no leading
#: dot, no path separator, no ``..`` component).
PACKAGE_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+\-]*")

#: A sha256 pin must be exactly 64 lowercase hex digits (after lowercasing).
SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class FlaggedPackage:
    """A resolved package whose lock entry names at least one platform wheel.

    A platform wheel tag (anything but ``any``) means compiled native
    extensions, which can statically link another toolchain's packages that no
    lockfile in the scanned tree describes. ``sdist_url`` and ``sdist_sha256``
    are both present only when the lock pins the sdist by sha256 -- the only
    state that authorizes a fetch.
    """

    name: str
    version: str
    lock_display: str
    sdist_url: Optional[str] = None
    sdist_sha256: Optional[str] = None
    sdist_size: Optional[int] = None
    #: Why the entry must not be harvested (an identifier or pin that failed
    #: validation); None for an entry the harvest may act on. The converter
    #: records the skip and fetches nothing for a rejected entry.
    rejected_reason: Optional[str] = None

    @property
    def parent_purl(self) -> str:
        """The package-url of the resolved PyPI package the harvest covers."""
        return f"pkg:pypi/{self.name}@{self.version}"


@dataclass
class HarvestManifest:
    """What ``harvest-manifest.json`` records beside each package's lockfiles."""

    package: str
    version: str
    parent_purl: str
    sdist_url: str
    sdist_sha256: str
    lockfiles: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(
            {
                "package": self.package,
                "version": self.version,
                "parent_purl": self.parent_purl,
                "sdist_url": self.sdist_url,
                "sdist_sha256": self.sdist_sha256,
                "lockfiles": self.lockfiles,
            },
            indent=2,
        )


def is_platform_wheel_filename(filename: str) -> bool:
    """Whether a wheel filename carries a platform tag other than ``any``.

    The wheel filename grammar is ``{dist}-{version}(-{build})?-{python}-{abi}-
    {platform}.whl``; a pure-Python wheel ends ``...-none-any.whl`` while a
    compiled one names its platform (``manylinux_2_17_x86_64``, ``win_amd64``).
    The tag is machine-readable in the lock itself, so no artifact is ever
    fetched to make this decision. A name the grammar cannot parse is NOT
    flagged: the conservative side of an autodetection that triggers a fetch is
    to not fetch.
    """
    if not filename.endswith(".whl"):
        return False
    stem = filename[: -len(".whl")]
    parts = stem.split("-")
    # dist, version, [build,] python, abi, platform: five parts at minimum.
    if len(parts) < 5:
        return False
    return parts[-1] != "any"


def flagged_packages_in_uv_lock(
    lock_bytes: bytes, lock_display: str
) -> List[FlaggedPackage]:
    """Every package entry of a ``uv.lock`` that names a platform wheel.

    Args:
        lock_bytes: The lockfile's content.
        lock_display: The lockfile's path as reports show it (relative to the
            scanned tree), carried onto each flagged package.

    Returns:
        The flagged packages in lockfile order. A flagged entry whose ``sdist``
        pins no ``sha256:`` hash is returned with ``sdist_url``/``sdist_sha256``
        of None, so the caller can report the skip instead of fetching
        unverified bytes.

    Raises:
        ValueError: The bytes are not TOML, or not a uv lockfile shape. The
            caller records the file as a skipped input; its content is never
            quoted.
    """
    try:
        document = tomllib.loads(lock_bytes.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ValueError(
            f"{lock_display} is not a TOML document ({type(error).__name__})"
        ) from None
    packages = document.get("package")
    if packages is None:
        return []
    if not isinstance(packages, list):
        raise ValueError(f"{lock_display} has no package list a uv.lock would have")
    flagged: List[FlaggedPackage] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        wheels = entry.get("wheels")
        if not isinstance(wheels, list):
            continue
        has_platform_wheel = False
        for wheel in wheels:
            if not isinstance(wheel, dict):
                continue
            url = wheel.get("url")
            if isinstance(url, str) and is_platform_wheel_filename(
                url.rsplit("/", 1)[-1]
            ):
                has_platform_wheel = True
                break
        if not has_platform_wheel:
            continue
        sdist_url: Optional[str] = None
        sdist_sha256: Optional[str] = None
        sdist_size: Optional[int] = None
        rejected_reason: Optional[str] = None
        sdist = entry.get("sdist")
        if isinstance(sdist, dict):
            url_value = sdist.get("url")
            hash_value = sdist.get("hash")
            size_value = sdist.get("size")
            if isinstance(url_value, str) and url_value:
                sdist_url = url_value
            if isinstance(hash_value, str) and hash_value.startswith("sha256:"):
                candidate = hash_value[len("sha256:") :].lower()
                if SHA256_HEX_RE.fullmatch(candidate):
                    sdist_sha256 = candidate
                else:
                    rejected_reason = (
                        "its lock entry's sdist sha256 pin is not a 64-character "
                        "hex digest"
                    )
            if isinstance(size_value, int) and size_value >= 0:
                sdist_size = size_value
        if not (
            PACKAGE_IDENTIFIER_RE.fullmatch(name)
            and PACKAGE_IDENTIFIER_RE.fullmatch(version)
        ):
            rejected_reason = (
                "its lock entry's name or version is not a valid package "
                "identifier (letters, digits and . _ - + only, no leading dot)"
            )
        flagged.append(
            FlaggedPackage(
                name=name,
                version=version,
                lock_display=lock_display,
                sdist_url=sdist_url,
                sdist_sha256=sdist_sha256,
                sdist_size=sdist_size,
                rejected_reason=rejected_reason,
            )
        )
    return flagged


def _usable_member(member: tarfile.TarInfo) -> bool:
    """Whether an archive member may be READ as a lockfile candidate.

    Only regular files. Links of any kind are not followed (a link's target is
    the archive author's choice, not ours), and a member whose path is absolute
    or climbs with ``..`` is not read at all -- defense in depth on top of the
    placement rule, which never uses member paths for filesystem placement.
    """
    if not member.isreg():
        return False
    posix = PurePosixPath(member.name)
    if posix.is_absolute():
        return False
    if ".." in posix.parts:
        return False
    return True


def harvest_lockfiles_from_sdist(
    archive_path: Path,
    wanted_basenames: Sequence[str],
    destination: Path,
) -> List[str]:
    """Materialize the recognized embedded lockfiles of a VERIFIED sdist.

    The caller has already verified the archive against the lock's sha256 pin
    (``download_utils`` does it while the bytes are still in a temporary file);
    this function only reads it. For each wanted basename the SHALLOWEST
    matching member wins (the workspace lockfile at the archive root over a
    vendored crate's own copy deeper in), ties going to the first member in
    archive order. Content is written to ``destination/<basename>`` -- a path
    built here, never one from the archive -- so no member path can place a
    byte anywhere else. ``extractall`` is never called.

    Returns:
        The basenames written, sorted. An sdist that ships none of the wanted
        files returns an empty list, which the caller reports as a skip.
    """
    wanted = set(wanted_basenames)
    chosen: Dict[str, Tuple[int, tarfile.TarInfo]] = {}
    written: List[str] = []
    with tarfile.open(archive_path, mode="r:*") as archive:
        for member in archive:
            if not _usable_member(member):
                continue
            posix = PurePosixPath(member.name)
            if posix.name not in wanted:
                continue
            if member.size > MAX_LOCKFILE_MEMBER_BYTES:
                ASH_LOGGER.debug(
                    f"sdist member '{member.name}' is larger than "
                    f"{MAX_LOCKFILE_MEMBER_BYTES} bytes and is not harvested",
                    extra=NO_MARKUP,
                )
                continue
            depth = len(posix.parts)
            held = chosen.get(posix.name)
            if held is None or depth < held[0]:
                chosen[posix.name] = (depth, member)
        for basename in sorted(chosen):
            _depth, member = chosen[basename]
            handle = archive.extractfile(member)
            if handle is None:
                continue
            with handle:
                content = handle.read(MAX_LOCKFILE_MEMBER_BYTES + 1)
            if len(content) > MAX_LOCKFILE_MEMBER_BYTES:
                # A member whose header understated its size (a sparse trick);
                # the size check above already filtered honest headers.
                continue
            destination.mkdir(parents=True, exist_ok=True)
            write_bytes_atomically(
                destination.joinpath(basename), content, root=destination
            )
            written.append(basename)
    return written


def harvest_manifests_under(target: Path) -> Dict[Tuple[str, str], HarvestManifest]:
    """Every harvest manifest under ``target``, keyed by (package, version).

    The walk is bounded to ``**/sdist-locks/*/*/harvest-manifest.json``, the one
    layout the harvester writes, so an unrelated file of the same name elsewhere
    in the converted target is not read. A manifest that cannot be read or is
    not the recorded shape is skipped with a debug line: provenance stamping is
    an enrichment and never fails a scan.
    """
    manifests: Dict[Tuple[str, str], HarvestManifest] = {}
    root = Path(target)
    if not root.is_dir():
        return manifests
    for manifest_path in sorted(
        root.glob(f"**/{HARVEST_DIR_NAME}/*/*/{HARVEST_MANIFEST_NAME}")
    ):
        try:
            record = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest = HarvestManifest(
                package=record["package"],
                version=record["version"],
                parent_purl=record["parent_purl"],
                sdist_url=record["sdist_url"],
                sdist_sha256=record["sdist_sha256"],
                lockfiles=list(record.get("lockfiles", [])),
            )
        except Exception as error:
            ASH_LOGGER.debug(
                f"skipping a harvest manifest that is not the recorded shape "
                f"({type(error).__name__})",
                extra=NO_MARKUP,
            )
            continue
        manifests[(manifest.package, manifest.version)] = manifest
    return manifests


def _harvest_owner_of(path_value: str) -> Optional[Tuple[str, str]]:
    """The (package, version) of a location under a harvest directory, or None.

    ``path_value`` is a ``syft:location:N:path`` property value, spelled from
    syft's base path (``/work/sdist-lock-harvester/sdist-locks/<name>/<ver>/...``
    or a relative form). The two segments after ``sdist-locks`` are the
    harvester's layout.
    """
    parts = PurePosixPath(path_value).parts
    for index, part in enumerate(parts):
        if part == HARVEST_DIR_NAME and index + 2 < len(parts):
            return (parts[index + 1], parts[index + 2])
    return None


def stamp_harvested_components(report: "CycloneDXReport", target: Path) -> int:
    """Stamp provenance properties onto components harvested from sdists.

    Every component of ``report`` whose syft location falls under a
    ``sdist-locks/<package>/<version>/`` directory gains three CycloneDX
    properties from that directory's manifest: the sdist's sha256 (the lock's
    pin, re-verified at fetch), the parent package's purl, and the sdist URL.
    Idempotent: a component already carrying the sha256 property is not stamped
    again (one ``scan()`` call builds a fresh report, but the cost of the guard
    is nothing and it makes reruns over a parsed document safe).

    Returns:
        How many components were stamped.
    """
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import Property

    components = getattr(report, "components", None)
    if not components:
        return 0
    manifests = harvest_manifests_under(target)
    if not manifests:
        return 0
    stamped = 0
    for component in components:
        properties = getattr(component, "properties", None) or []
        if any(
            getattr(prop, "name", "") == PROPERTY_SDIST_SHA256 for prop in properties
        ):
            continue
        owner: Optional[Tuple[str, str]] = None
        for prop in properties:
            name = getattr(prop, "name", "")
            value = getattr(prop, "value", None)
            if (
                isinstance(name, str)
                and name.startswith("syft:location:")
                and name.endswith(":path")
                and isinstance(value, str)
            ):
                owner = _harvest_owner_of(value)
                if owner is not None and owner in manifests:
                    break
                owner = None
        if owner is None:
            continue
        manifest = manifests[owner]
        new_properties = list(properties) + [
            Property(name=PROPERTY_SDIST_SHA256, value=manifest.sdist_sha256),
            Property(name=PROPERTY_PARENT_PURL, value=manifest.parent_purl),
            Property(name=PROPERTY_SOURCE_URL, value=manifest.sdist_url),
        ]
        component.properties = new_properties
        stamped += 1
    return stamped


def harvest_options_of(config: object) -> Mapping[str, object]:
    """The ``sdist_harvest`` option group of the syft scanner's config section.

    Read duck-typed from the scan's ``AshConfig`` (``scanners.syft.options.
    sdist_harvest``), because the group lives on the syft scanner's options
    surface (it owns SBOM configuration) while the harvest itself runs in the
    convert phase. Returns a plain mapping with every key defaulted, so the
    harvester behaves identically whether the section is typed, absent, or an
    operator override. The syft scanner being DISABLED (``syft_enabled``) means
    nothing is fetched: the harvest exists to complete the SBOM that scanner
    produces. The converter then only names what it did not harvest, for the
    readers :func:`harvest_advisory_readers_that_run` finds.
    """
    defaults: Dict[str, object] = {
        "enabled": True,
        "syft_enabled": True,
        "syft_offline": False,
        "ecosystems": list(ECOSYSTEM_LOCKFILES),
        "max_sdist_mb": 100,
        "cache_dir": None,
        "lockfiles": ["uv.lock"],
    }
    scanners = getattr(config, "scanners", None)
    syft = getattr(scanners, "syft", None)
    if syft is None:
        return defaults
    enabled = getattr(syft, "enabled", True)
    defaults["syft_enabled"] = bool(enabled) if isinstance(enabled, bool) else True
    options = getattr(syft, "options", None)
    syft_offline = getattr(options, "offline", False)
    defaults["syft_offline"] = (
        bool(syft_offline) if isinstance(syft_offline, bool) else False
    )
    group = getattr(options, "sdist_harvest", None)
    if group is None:
        return defaults
    enabled_value = getattr(group, "enabled", True)
    if isinstance(enabled_value, bool):
        defaults["enabled"] = enabled_value
    ecosystems = getattr(group, "ecosystems", None)
    if isinstance(ecosystems, (list, tuple)):
        defaults["ecosystems"] = [
            item for item in ecosystems if isinstance(item, str) and item
        ]
    max_mb = getattr(group, "max_sdist_mb", None)
    if isinstance(max_mb, int) and max_mb > 0:
        defaults["max_sdist_mb"] = max_mb
    cache_dir = getattr(group, "cache_dir", None)
    if cache_dir is not None and str(cache_dir).strip():
        defaults["cache_dir"] = cache_dir
    lockfiles = getattr(group, "lockfiles", None)
    if isinstance(lockfiles, (list, tuple)):
        defaults["lockfiles"] = [
            item for item in lockfiles if isinstance(item, str) and item
        ]
    return defaults


#: The scanners besides syft that read the harvested lockfiles from the converted
#: target, to match advisories against the packages they name. With the syft
#: scanner disabled nothing is fetched, and the converter names the packages it
#: did not harvest only for the ones of these that run.
HARVEST_ADVISORY_READERS: Tuple[str, ...] = ("grype", "trivy")


def harvest_advisory_readers_that_run(
    config: object, selection: object = None
) -> List[str]:
    """The scanners of ``HARVEST_ADVISORY_READERS`` that this run runs.

    A reader runs when its config section leaves it enabled and the run's
    scanner selection keeps it. The section is read with ``section_enabled``,
    the one reading of ``enabled`` the phases share, from the section
    ``get_plugin_config`` returns, or from the ``scanners`` attribute of a
    config that has no such method. An absent section, and a lookup that
    raises, read as enabled, as an absent syft section does in
    :func:`harvest_options_of`: a record that names a gap no reader has is
    noise, while a missing one hides a gap.

    ``selection`` is the context's ``scanner_selection``, which the engine
    records. It leaves a reader out as the scan phase does: an exclusion names
    it, an allowlist is given and does not name it, or the run is Python-only
    and the reader's class says it is not Python-only. A reader is named by its
    section's ``name``, else by its own, and names compare through
    ``selection_key``. With no selection (a context no engine was built over)
    none is left out. The shards of a split scan are not told apart: each
    shard names the readers the selection keeps for the whole scan.
    """
    from automated_security_helper.base.plugin_config import section_enabled
    from automated_security_helper.utils.scanner_names import selection_key
    from automated_security_helper.utils.scanner_tool_types import (
        scanner_declares_python_only,
    )

    lookup = getattr(config, "get_plugin_config", None)
    scanners = getattr(config, "scanners", None)
    allowlist = {selection_key(name) for name in getattr(selection, "enabled", ())}
    excluded = {selection_key(name) for name in getattr(selection, "excluded", ())}
    python_only = bool(getattr(selection, "python_only", False))
    running: List[str] = []
    for name in HARVEST_ADVISORY_READERS:
        if callable(lookup):
            try:
                section = lookup("scanner", name)
            except Exception:
                section = None
        else:
            section = getattr(scanners, name, None)
        if not section_enabled(section):
            continue
        key = selection_key(_selected_as(section, name))
        if key in excluded or (allowlist and key not in allowlist):
            continue
        if python_only and scanner_declares_python_only(name) is False:
            continue
        running.append(name)
    return running


def _selected_as(section: object, name: str) -> str:
    """The name a scanner is selected by: its section's ``name``, else ``name``.

    The scan phase matches a selection against ``config.name`` on each scanner,
    which a section can set, so the reader is judged by the same name.
    """
    if isinstance(section, dict):
        configured = section.get("name")
    else:
        configured = getattr(section, "name", None)
    if isinstance(configured, str) and configured:
        return configured
    return name
