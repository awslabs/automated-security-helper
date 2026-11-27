# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the SdistLockHarvester converter implementation."""

import json
import ntpath
import shutil
import tempfile
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
    cast,
)

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.plugin_context import context_ash_config
from automated_security_helper.core.constants import is_offline_mode
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)
from automated_security_helper.plugins.decorators import ash_converter_plugin
from automated_security_helper.utils.atomic_write import (
    write_bytes_atomically,
    write_text_atomically,
)
from automated_security_helper.utils.download_utils import download_file
from automated_security_helper.utils.get_scan_set import honors_ignore_files, scan_set
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.scan_output_dirs import record_converted_sources
from automated_security_helper.utils.scanned_tree import TreeInputRefused
from automated_security_helper.utils.sdist_harvest import (
    ECOSYSTEM_LOCKFILES,
    HARVEST_DIR_NAME,
    HARVEST_MANIFEST_NAME,
    HARVEST_SKIPPED_RULE,
    FlaggedPackage,
    HarvestManifest,
    default_harvest_cache_root,
    flagged_packages_in_uv_lock,
    harvest_lockfiles_from_sdist,
    harvest_options_of,
)
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    ignore_path_matches,
)


def confined_path(root: Path, *parts: str) -> Optional[Path]:
    """``root`` joined with ``parts``, resolved, if it stays strictly under ``root``.

    The harvest builds paths from values a scanned repository wrote (package
    name, version, a cache key). Those are validated at parse time; this is the
    second layer at every join site: the joined path is resolved (symlinks and
    ``..`` included) and must be inside the resolved root, and not the root
    itself. None means refuse: the caller skips the package and never deletes
    or writes the path.
    """
    try:
        resolved_root = Path(root).resolve()
        joined = resolved_root.joinpath(*parts).resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if joined == resolved_root or not joined.is_relative_to(resolved_root):
        return None
    return joined


class SdistLockHarvesterConverterConfig(ConverterPluginConfigBase):
    """Configuration for the sdist lockfile harvester.

    The feature's OPTIONS live on the syft scanner's options surface
    (``scanners.syft.options.sdist_harvest``), because that is where the
    operator already configures SBOM behavior and where ASH's config trust
    machinery polices who wrote a value. This section only turns the converter
    itself on or off; with the converter on, ``sdist_harvest.enabled`` and
    offline mode decide whether anything is fetched.
    """

    name: Literal["sdist-lock-harvester"] = "sdist-lock-harvester"
    enabled: bool = True


@ash_converter_plugin
class SdistLockHarvester(ConverterPluginBase[SdistLockHarvesterConverterConfig]):
    """Harvests cross-toolchain lockfiles from the sdists the tree's lockfiles pin.

    A resolved Python dependency whose wheels carry a platform tag ships compiled
    native extensions, which can statically link another toolchain's packages
    (polars' Rust crates are the measured case) that nothing in the scanned tree
    describes, so the SBOM silently omits them. Artifacts that carry audit data
    (cargo-auditable binaries, Go buildinfo) are already read by syft's own
    catalogers; this converter covers the packages with NO audit data by fetching
    the HASH-PINNED sdist the project's own ``uv.lock`` resolves -- online mode
    only, verified against the lock's sha256 before anything is extracted -- and
    materializing only its recognized embedded lockfiles
    (``Cargo.lock``, ``go.sum``, ``package-lock.json``) into the converted
    target, under ``sdist-locks/<package>/<version>/``, beside a provenance
    manifest. The existing pinned scanners then read them in their ordinary
    converted-target pass: syft indexes the packages into the SBOM, and grype and
    trivy match advisories against them. Offline, or on any refused fetch, the
    affected packages are skipped and recorded as one visible
    ``ash-sbom-harvest-skipped`` fact per cause, never a silent gap; a cache in
    the user-level cache directory -- outside the scanned tree, keyed by the
    sdist's sha256, each file re-verified against its recorded digest before it
    is served -- serves warmed entries without network even offline.
    """

    display_name = "Sdist lock harvester"
    docs_summary = (
        "Harvests embedded lockfiles from hash-pinned sdists of compiled "
        "dependencies, so the SBOM covers cross-toolchain packages"
    )

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SdistLockHarvesterConverterConfig()
        return super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Entirely Python based: tomllib, tarfile and the download utils."""
        self.dependencies_satisfied = True
        return True

    # ------------------------------------------------------------------
    # Input discovery
    # ------------------------------------------------------------------

    def _lockfiles_in_scan_set(self, lockfile_names: List[str]) -> List[str]:
        """Every configured Python lockfile in the scan set, by basename.

        The scan set applies ``.gitignore``/``.ignore`` and this run's output
        directories, the same reading every built-in converter takes.
        """
        workspace_output_dir = getattr(self.context, "workspace_output_dir", None)
        wanted = set(lockfile_names)
        context = self._require_context()
        files = scan_set(
            source=context.source_dir,
            output=context.output_dir,
            honor_ignore_files=honors_ignore_files(context.config),
            run_id=getattr(self.context, "run_id", None),
            workspace_output_dir=(
                None if workspace_output_dir is None else str(workspace_output_dir)
            ),
        )
        # scan_set paths come from os.path.join, so on Windows they carry
        # backslashes; ntpath.basename splits on either separator on every
        # platform, so the match does not depend on where the run executes.
        return [f for f in files if ntpath.basename(f) in wanted]

    def _ignore_paths_skipping_harvest(self) -> List[IgnorePathWithReason]:
        return ignore_paths_that_skip_scanning(
            active_ignore_paths(
                context_ash_config(
                    self._require_context(), self.__class__.__name__
                ).global_settings.ignore_paths
            ),
            ignore_suppressions=getattr(self.context, "ignore_suppressions", False),
        )

    def _ignored_by(
        self, lock_file: str, ignore_paths: List[IgnorePathWithReason]
    ) -> Optional[IgnorePathWithReason]:
        from automated_security_helper.utils.scanned_tree import relative_display

        display = relative_display(lock_file, self._require_context().source_dir)
        for item in ignore_paths:
            if ignore_path_matches(display, item.path):
                return item
        return None

    def candidate_input_count(self) -> int | None:
        """How many configured lockfiles the harvest would walk; see the base.

        Counted without network: the fetch decision is per package entry, but
        coverage is asked per input file, the same denominator the scan set
        gives the other converters.
        """
        try:
            options = harvest_options_of(getattr(self.context, "config", None))
            if not (options["enabled"] and options["syft_enabled"]):
                return 0
            ignore_paths = self._ignore_paths_skipping_harvest()
            return len(
                [
                    lock
                    for lock in self._lockfiles_in_scan_set(
                        list(cast(Iterable[str], options["lockfiles"]))
                    )
                    if self._ignored_by(lock, ignore_paths) is None
                ]
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------

    def _cache_root(self, configured: object) -> Optional[Path]:
        """Where verified harvests are cached, keyed by sdist sha256; None for none.

        The default is the user-level cache directory
        (``sdist_harvest.default_harvest_cache_root``), never a directory under
        the scanned tree or the scan's output directory: the default output
        layout sits INSIDE the scanned tree, where a repository could commit a
        pre-warmed entry and have its own bytes served as a verified harvest.
        An operator may point ``cache_dir`` at a persistent location (a CI
        cache volume); the configured value goes through the same
        operator-trust gate the syft ``config_file`` option uses -- which
        refuses a path inside the scanned tree whoever named it -- and a
        refused value falls back to the default rather than being honored.
        Whatever root results is held to the same line once more below, and
        None (no usable root at all) makes the caller cache in a private
        per-run directory that no repository content can pre-fill.
        """
        root: Optional[Path] = None
        if configured is not None:
            from automated_security_helper.config.operator_only_options import (
                operator_wrote_value,
            )
            from automated_security_helper.config.path_trust import honored_path

            context_config = getattr(self.context, "config", None)
            root = honored_path(
                cast(Union[str, Path], configured),
                source_dir=Path(self._require_context().source_dir),
                config=context_config,
                key="scanners.syft.options.sdist_harvest.cache_dir",
                operator_written=operator_wrote_value(
                    context_config,
                    "scanner",
                    "syft",
                    ("options", "sdist_harvest", "cache_dir"),
                    configured,
                    config_from_context=self._config_from_context,
                ),
            )
            if root is None:
                ASH_LOGGER.warning(
                    "Configured sdist-harvest cache directory was not used "
                    "(scanners.syft.options.sdist_harvest.cache_dir): it is inside "
                    "the scanned tree, was delivered by an MCP client, or was "
                    "derived from the repository. The cache falls back to the "
                    "user-level default."
                )
        if root is None:
            root = default_harvest_cache_root()
            if root is None:
                ASH_LOGGER.warning(
                    "There is no usable home directory and no absolute "
                    "XDG_CACHE_HOME, so the sdist-harvest cache is a private "
                    "directory of this run alone: warmed entries will not "
                    "persist to the next run."
                )
                return None
        # Belt and suspenders over the two sources above: a cache inside the
        # scanned tree is a way for the repository to serve its own bytes as a
        # verified harvest, so such a root is never used, whoever named it
        # (scanning a directory that encloses the user cache included).
        from automated_security_helper.config.sandbox_grants import (
            UNFINISHED_WALK_REASON,
            in_tree_reason,
        )

        scan_root = (
            getattr(getattr(self.context, "config", None), "_scanned_root", None)
            or self._require_context().source_dir
        )
        try:
            reason = in_tree_reason(Path(root), Path(scan_root))
        except (OSError, RuntimeError):
            reason = UNFINISHED_WALK_REASON
        if reason is not None:
            ASH_LOGGER.warning(
                f"The sdist-harvest cache directory was not used: {reason}. "
                "The cache is a private directory of this run alone instead."
            )
            return None
        return root

    # ------------------------------------------------------------------
    # Harvest
    # ------------------------------------------------------------------

    def _materialize(
        self,
        package: FlaggedPackage,
        cached_dir: Path,
        lockfiles: List[str],
        sources: Dict[Path, str],
    ) -> List[Path]:
        """Copy a package's verified, cached lockfiles into the converted target.

        Layout: ``<results>/sdist-locks/<name>/<version>/<lockfile>`` beside
        ``harvest-manifest.json``. The manifest carries the provenance the syft
        scanner stamps onto each harvested component.
        """
        destination = confined_path(
            self._require_results_dir().joinpath(HARVEST_DIR_NAME),
            package.name,
            package.version,
        )
        if destination is None:
            raise RuntimeError("the harvest destination is outside its root")
        destination.mkdir(parents=True, exist_ok=True)
        written: List[Path] = []
        for basename in sorted(lockfiles):
            target = destination.joinpath(basename)
            write_bytes_atomically(
                target, cached_dir.joinpath(basename).read_bytes(), root=destination
            )
            written.append(target)
            sources[target] = package.lock_display
        manifest = HarvestManifest(
            package=package.name,
            version=package.version,
            parent_purl=package.parent_purl,
            sdist_url=package.sdist_url or "",
            sdist_sha256=package.sdist_sha256 or "",
            lockfiles=sorted(lockfiles),
        )
        manifest_path = destination.joinpath(HARVEST_MANIFEST_NAME)
        write_text_atomically(
            manifest_path, manifest.to_json() + "\n", "utf-8", root=destination
        )
        written.append(manifest_path)
        sources[manifest_path] = package.lock_display
        return written

    def _cached_lockfiles(
        self, cache_root: Path, package: FlaggedPackage, ecosystems: List[str]
    ) -> Optional[List[str]]:
        """The cached harvest for a package's pinned sdist, or None on a miss.

        The cache key is the lock's sha256, so an entry can never serve a
        different sdist than the lock pins; the key being the verification is
        what makes a warmed cache usable offline. The KEY authorizes the entry,
        and the digests recorded when the entry was written tie the served
        BYTES to it: every file about to be served is hashed again here, and
        one that does not match -- or an entry recorded without digests -- is
        not served: the entry is evicted and the package reads as a cold miss,
        so tampered or unverifiable cache bytes never reach the converted
        target. Only the basenames the configured ecosystems name are served,
        so narrowing the option narrows a warmed cache too.
        """
        if package.sdist_sha256 is None:
            return None
        entry = confined_path(cache_root, package.sdist_sha256)
        if entry is None:
            return None
        index = entry.joinpath("cached-lockfiles.json")
        if not index.is_file():
            return None
        try:
            cached = json.loads(index.read_text(encoding="utf-8"))
            names = list(cached.get("lockfiles", []))
            digests = cached.get("digests")
        except Exception as error:
            self._evict_cache_entry(
                cache_root,
                entry,
                f"its index could not be read ({type(error).__name__})",
            )
            return None
        if not isinstance(digests, dict):
            self._evict_cache_entry(
                cache_root, entry, "its index records no content digests"
            )
            return None
        from automated_security_helper.utils.download_utils import sha256_file

        wanted = {
            ECOSYSTEM_LOCKFILES[eco] for eco in ecosystems if eco in ECOSYSTEM_LOCKFILES
        }
        served = [name for name in names if name in wanted]
        for name in served:
            recorded = digests.get(name)
            candidate = confined_path(entry, name)
            try:
                matches = (
                    isinstance(recorded, str)
                    and candidate is not None
                    and candidate.is_file()
                    and sha256_file(candidate).lower() == recorded.lower()
                )
            except OSError:
                matches = False
            if not matches:
                self._evict_cache_entry(
                    cache_root,
                    entry,
                    f"'{name}' does not match the digest recorded when the "
                    "entry was written",
                )
                return None
        return served

    def _evict_cache_entry(self, cache_root: Path, entry: Path, why: str) -> None:
        """Remove a cache entry that cannot be served, so the miss is honest.

        Serving is refused on ANY doubt; eviction then makes the next online
        run re-fetch and re-verify against the lock's pin instead of meeting
        the same unverifiable bytes again. The caller then answers None, its
        cold miss.
        """
        confined = confined_path(cache_root, entry.name)
        if confined is None or confined != Path(entry).resolve():
            ASH_LOGGER.warning(
                "Not evicting a sdist-harvest cache entry that is outside the "
                "cache root; the package reads as a cold cache miss."
            )
            return None
        ASH_LOGGER.warning(
            f"Evicting the sdist-harvest cache entry {entry.name[:12]}...: {why}. "
            "The package reads as a cold cache miss."
        )
        shutil.rmtree(confined, ignore_errors=True)
        return None

    def _fetch_and_harvest(
        self,
        cache_root: Path,
        package: FlaggedPackage,
        ecosystems: List[str],
        max_sdist_bytes: int,
    ) -> List[str]:
        """Download the pinned sdist, verify, harvest, and fill the cache entry.

        The download lands in a private staging directory and is VERIFIED
        against the lock's sha256 before any extraction: ``download_file`` is
        given ``expected_sha256`` and hashes the bytes while they are still in
        its temporary file, so a mismatch raises ``ToolDownloadIntegrityError``
        and leaves nothing on disk for the extractor to open. The transfer is
        bounded on the wire too: ``max_bytes`` aborts it past the configured
        ``max_sdist_mb`` (``DownloadTooLargeError``), so the lock's own size
        claim -- the scanned repository's claim -- cannot buy an unbounded
        download. The verified archive is read for the recognized lockfile
        basenames only and then deleted; the cache keeps the extracted
        lockfiles, keyed by the pin, beside the sha256 of each written file,
        which every later read re-verifies before serving.
        """
        if package.sdist_url is None or package.sdist_sha256 is None:
            # _harvest_one skips such a package before calling here; this guard
            # keeps the invariant local instead of trusting the caller.
            raise RuntimeError("a fetch needs the lock's sdist URL and sha256 pin")
        from automated_security_helper.utils.download_utils import sha256_file

        wanted = [
            ECOSYSTEM_LOCKFILES[eco] for eco in ecosystems if eco in ECOSYSTEM_LOCKFILES
        ]
        confined_entry = confined_path(cache_root, package.sdist_sha256)
        if confined_entry is None:
            raise RuntimeError("the cache entry is outside the cache root")
        entry = confined_entry
        entry.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="ash-sdist-harvest-", dir=cache_root
        ) as staging:
            # Hash verified before any extraction: expected_sha256 is the lock's
            # pin, and a mismatch raises with the staged file already removed.
            archive = download_file(
                package.sdist_url,
                Path(staging),
                expected_sha256=package.sdist_sha256,
                max_bytes=max_sdist_bytes,
            )
            harvested = harvest_lockfiles_from_sdist(archive, wanted, entry)
        # Replaced whole, so a concurrent scan reading this entry sees the old
        # index or the new one, never a truncated file it would evict as torn.
        write_text_atomically(
            entry.joinpath("cached-lockfiles.json"),
            json.dumps(
                {
                    "sha256": package.sdist_sha256,
                    "lockfiles": harvested,
                    "digests": {
                        name: sha256_file(entry.joinpath(name)) for name in harvested
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return harvested

    # ------------------------------------------------------------------
    # The convert() contract
    # ------------------------------------------------------------------

    def convert(self) -> List[Path]:
        """Harvest embedded lockfiles for every flagged package; see the class.

        Returns the files written under the converted target. Skips are grouped
        into one ``ash-sbom-harvest-skipped`` record per cause, each naming the
        packages it covers, so an SBOM's incompleteness is a visible fact and
        one cause does not scatter into a record per lockfile.
        """
        options = harvest_options_of(getattr(self.context, "config", None))
        if not options["enabled"]:
            ASH_LOGGER.debug(
                "sdist lockfile harvest is disabled "
                "(scanners.syft.options.sdist_harvest.enabled)"
            )
            return []
        if not options["syft_enabled"]:
            ASH_LOGGER.debug(
                "sdist lockfile harvest is skipped: the syft scanner is disabled, "
                "and the harvest exists to complete the SBOM it produces"
            )
            return []
        lockfile_names = list(cast(Iterable[str], options["lockfiles"]))
        lock_files = self._lockfiles_in_scan_set(lockfile_names)
        if not lock_files:
            ASH_LOGGER.debug(
                f"No {', '.join(lockfile_names) or 'configured'} lockfiles in "
                f"{self._require_context().source_dir}; nothing to harvest"
            )
            return []

        ecosystems = list(cast(Iterable[str], options["ecosystems"]))
        max_sdist_bytes = (
            int(cast(Union[int, str], options["max_sdist_mb"])) * 1024 * 1024
        )
        offline = is_offline_mode() or bool(options["syft_offline"])
        cache_root = self._cache_root(options["cache_dir"])
        run_private_cache: Optional[tempfile.TemporaryDirectory[str]] = None
        if cache_root is None:
            # No usable persistent root (_cache_root said why): cache in a
            # private directory of this run alone, which no repository content
            # can pre-fill, and remove it with the run.
            run_private_cache = tempfile.TemporaryDirectory(prefix="ash-sdist-harvest-")
            cache_root = Path(run_private_cache.name)
        ignore_paths = self._ignore_paths_skipping_harvest()

        self._require_results_dir().mkdir(parents=True, exist_ok=True)
        results: List[Path] = []
        sources: Dict[Path, str] = {}
        # cause -> [(lock display, "name version (sha prefix)"), ...]; one
        # grouped record per cause below.
        skips: Dict[str, List[Tuple[str, str]]] = {}

        def skip(package: FlaggedPackage, cause: str) -> None:
            prefix = (
                (package.sdist_sha256 or "")[:12] + "..."
                if package.sdist_sha256
                else "no sdist sha256 pin"
            )
            skips.setdefault(cause, []).append(
                (package.lock_display, f"{package.name} {package.version} ({prefix})")
            )

        try:
            for lock_file in lock_files:
                if Path(lock_file).is_dir():
                    continue
                ignored_by = self._ignored_by(lock_file, ignore_paths)
                if ignored_by is not None:
                    ASH_LOGGER.debug(
                        f"Skipping harvest of ignored path: {lock_file} due to "
                        f"global ignore_path '{ignored_by.path}' with reason "
                        f"'{ignored_by.reason}'",
                        extra=NO_MARKUP,
                    )
                    continue
                try:
                    handle = self.open_source_file(lock_file)
                except TreeInputRefused as refused:
                    self.record_refused_input(refused)
                    continue
                from automated_security_helper.utils.scanned_tree import (
                    relative_display,
                )

                display = relative_display(
                    lock_file, self._require_context().source_dir
                )
                with handle:
                    lock_bytes = handle.read()
                try:
                    flagged = flagged_packages_in_uv_lock(lock_bytes, display)
                except ValueError as error:
                    self.record_failed_input(lock_file, str(error), kind="input")
                    continue
                if not flagged:
                    ASH_LOGGER.debug(
                        f"{display}: no resolved package names a platform wheel; "
                        "nothing to harvest",
                        extra=NO_MARKUP,
                    )
                    continue
                for package in flagged:
                    try:
                        self._harvest_one(
                            package,
                            cache_root=cache_root,
                            ecosystems=ecosystems,
                            max_sdist_bytes=max_sdist_bytes,
                            offline=offline,
                            results=results,
                            sources=sources,
                            skip=skip,
                        )
                    except Exception as error:
                        # The type only: a fetch error's text can quote a URL the
                        # configuration read from the environment, and a skip's
                        # reason is recorded without it.
                        skip(package, f"the harvest raised {type(error).__name__}")
        finally:
            if run_private_cache is not None:
                run_private_cache.cleanup()

        for cause, entries in sorted(skips.items()):
            lock_display = entries[0][0]
            named = ", ".join(detail for _lock, detail in entries)
            self.record_refused_input(
                TreeInputRefused(
                    path=lock_display,
                    reason=(
                        f"{HARVEST_SKIPPED_RULE}: {cause}; the SBOM does not "
                        f"cover the embedded lockfiles of: {named}"
                    ),
                )
            )

        if sources:
            record_converted_sources(
                self._require_results_dir(), self._require_work_dir(), sources
            )
        return results

    def _harvest_one(
        self,
        package: FlaggedPackage,
        *,
        cache_root: Path,
        ecosystems: List[str],
        max_sdist_bytes: int,
        offline: bool,
        results: List[Path],
        sources: Dict[Path, str],
        skip: Callable[[FlaggedPackage, str], None],
    ) -> None:
        """Harvest one flagged package, or record why it was skipped."""
        if package.rejected_reason is not None:
            skip(package, package.rejected_reason)
            return
        if package.sdist_url is None or package.sdist_sha256 is None:
            skip(
                package,
                "its lock entry pins no sdist by sha256, so no fetch is authorized",
            )
            return
        cached = self._cached_lockfiles(cache_root, package, ecosystems)
        if cached is not None:
            if not cached:
                skip(
                    package,
                    "its sdist ships no recognized embedded lockfile "
                    f"({', '.join(sorted(ECOSYSTEM_LOCKFILES[e] for e in ecosystems if e in ECOSYSTEM_LOCKFILES))})",
                )
                return
            results.extend(
                self._materialize(
                    package,
                    self._confined_entry(cache_root, package),
                    cached,
                    sources,
                )
            )
            return
        if offline:
            skip(
                package,
                "offline mode is active and the harvest cache holds no entry "
                "for its pinned sdist",
            )
            return
        if package.sdist_size is not None and package.sdist_size > max_sdist_bytes:
            skip(
                package,
                "its pinned sdist is larger than the configured bound "
                "(scanners.syft.options.sdist_harvest.max_sdist_mb)",
            )
            return
        from automated_security_helper.core.exceptions import (
            DownloadTooLargeError,
            ToolDownloadIntegrityError,
        )

        try:
            harvested = self._fetch_and_harvest(
                cache_root, package, ecosystems, max_sdist_bytes
            )
        except DownloadTooLargeError:
            # The size-claim check above reads the LOCK's claim; this one read
            # the wire. The transfer was aborted at the bound, so a lying claim
            # cannot buy an unbounded download, and nothing was extracted.
            skip(
                package,
                "its sdist exceeded the configured bound on the wire "
                "(scanners.syft.options.sdist_harvest.max_sdist_mb); the "
                "transfer was aborted at the bound and nothing was extracted",
            )
            return
        except ToolDownloadIntegrityError:
            # The lock pins the digest the fetch was verified against; a
            # mismatch means the index served different bytes than the project
            # resolved, and nothing was extracted or cached.
            skip(
                package,
                "the fetched sdist did not match the lock's sha256 pin; "
                "nothing was extracted",
            )
            return
        except ValueError:
            skip(package, "its sdist URL is not https, so it was not fetched")
            return
        except OSError as error:
            skip(package, f"the fetch failed ({type(error).__name__})")
            return
        if not harvested:
            skip(
                package,
                "its sdist ships no recognized embedded lockfile "
                f"({', '.join(sorted(ECOSYSTEM_LOCKFILES[e] for e in ecosystems if e in ECOSYSTEM_LOCKFILES))})",
            )
            return
        results.extend(
            self._materialize(
                package,
                self._confined_entry(cache_root, package),
                harvested,
                sources,
            )
        )

    @staticmethod
    def _confined_entry(cache_root: Path, package: FlaggedPackage) -> Path:
        """The package's cache entry directory, confined to the cache root."""
        entry = confined_path(cache_root, package.sdist_sha256 or "")
        if entry is None:
            raise RuntimeError("the cache entry is outside the cache root")
        return entry
