# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Module containing the SdistLockHarvester converter implementation."""

import json
import ntpath
import shutil
import tempfile
from pathlib import Path
from typing import (
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Tuple,
    Union,
    cast,
)

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
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
    HARVEST_ADVISORY_READERS,
    HARVEST_DIR_NAME,
    HARVEST_MANIFEST_NAME,
    HARVEST_SKIPPED_RULE,
    FlaggedPackage,
    HarvestManifest,
    default_harvest_cache_root,
    flagged_packages_in_uv_lock,
    harvest_advisory_readers_that_run,
    harvest_lockfiles_from_sdist,
    harvest_options_of,
)
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    ignore_path_matches,
)

#: Why an entry that pins no sdist by sha256 is not harvested: nothing authorizes
#: a fetch of it, whatever the scanners' settings.
NO_SHA256_PIN_CAUSE = (
    "its lock entry pins no sdist by sha256, so no fetch is authorized"
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
    is served -- serves warmed entries without network even offline. With the
    syft scanner disabled nothing is fetched, and while grype or trivy runs the
    packages it would have harvested are named in a skip record instead.
    """

    display_name = "Sdist lock harvester"
    docs_summary = (
        "Harvests embedded lockfiles from hash-pinned sdists of compiled "
        "dependencies, so the SBOM covers cross-toolchain packages"
    )

    def model_post_init(self, context):
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
        files = scan_set(
            source=self.context.source_dir,
            output=self.context.output_dir,
            honor_ignore_files=honors_ignore_files(self.context.config),
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
            active_ignore_paths(self.context.config.global_settings.ignore_paths),
            ignore_suppressions=getattr(self.context, "ignore_suppressions", False),
        )

    def _ignored_by(
        self, lock_file: str, ignore_paths: List[IgnorePathWithReason]
    ) -> Optional[IgnorePathWithReason]:
        from automated_security_helper.utils.scanned_tree import relative_display

        display = relative_display(lock_file, self.context.source_dir)
        for item in ignore_paths:
            if ignore_path_matches(display, item.path):
                return item
        return None

    def candidate_input_count(self) -> int | None:
        """How many configured lockfiles convert() walks; see the base.

        Counted without network, by convert()'s own rules: none with the harvest
        disabled, and none with the syft scanner disabled and neither grype nor
        trivy running (enabled in its section and kept by the run's scanner
        selection), since convert() then returns before the walk. Otherwise
        every configured lockfile in the scan set that no ignore path skips,
        whether or not syft is on: with it off, convert() still walks them to
        name the packages it does not fetch. The fetch decision is per package
        entry, but coverage is asked per input file, the same denominator the
        scan set gives the other converters.
        """
        try:
            config = getattr(self.context, "config", None)
            options = harvest_options_of(config)
            if not options["enabled"]:
                return 0
            if not options["syft_enabled"] and not harvest_advisory_readers_that_run(
                config, getattr(self.context, "scanner_selection", None)
            ):
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
        Only the operator chooses where the cache lives, for example a
        persistent CI cache volume. A value from a config file inside a git
        checkout or the scanned directory, or from an MCP client, is not used
        wherever it points, and the cache falls back to the default. The
        operator's own value then goes through the same tree check the syft
        ``config_file`` option uses, which refuses a path inside the scanned
        tree whoever named it; that refusal falls back to the default as well.
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
            from automated_security_helper.utils.config_trust import (
                NOT_THE_OPERATORS,
                refusal_warning,
            )

            context_config = getattr(self.context, "config", None)
            operator_written = operator_wrote_value(
                context_config,
                "scanner",
                "syft",
                ("options", "sdist_harvest", "cache_dir"),
                configured,
                config_from_context=self._config_from_context,
            )
            if not operator_written:
                # Only the operator chooses where the cache lives, so a value
                # from a config file inside a git checkout or the scanned
                # directory, or from an MCP client, is not handed to
                # honored_path: wherever it points, it is not used. The warning
                # leaves the value out, since it is the repository's own text
                # and can be one the config read from the environment.
                ASH_LOGGER.warning(
                    refusal_warning(
                        "Configured sdist-harvest cache directory was not used "
                        "(scanners.syft.options.sdist_harvest.cache_dir): "
                        f"{NOT_THE_OPERATORS}, and only the operator chooses "
                        "where verified harvests are cached. The cache falls "
                        "back to the user-level default.",
                        NOT_THE_OPERATORS,
                    )
                )
            else:
                # The operator's own value still may not point into the
                # scanned tree.
                root = honored_path(
                    cast(Union[str, Path], configured),
                    source_dir=Path(self.context.source_dir),
                    config=context_config,
                    key="scanners.syft.options.sdist_harvest.cache_dir",
                    operator_written=True,
                )
                if root is None:
                    ASH_LOGGER.warning(
                        "Configured sdist-harvest cache directory was not used "
                        "(scanners.syft.options.sdist_harvest.cache_dir): it is "
                        "inside the scanned tree or a git checkout, an MCP "
                        "client delivered it, or its name could not be resolved "
                        "to the end. The cache falls back to the user-level "
                        "default."
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
            or self.context.source_dir
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
            self.results_dir.joinpath(HARVEST_DIR_NAME), package.name, package.version
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
            return self._evict_cache_entry(
                cache_root,
                entry,
                f"its index could not be read ({type(error).__name__})",
            )
        if not isinstance(digests, dict):
            return self._evict_cache_entry(
                cache_root, entry, "its index records no content digests"
            )
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
                return self._evict_cache_entry(
                    cache_root,
                    entry,
                    f"'{name}' does not match the digest recorded when the "
                    "entry was written",
                )
        return served

    def _evict_cache_entry(self, cache_root: Path, entry: Path, why: str) -> None:
        """Remove a cache entry that cannot be served, so the miss is honest.

        Serving is refused on ANY doubt; eviction then makes the next online
        run re-fetch and re-verify against the lock's pin instead of meeting
        the same unverifiable bytes again. Returns None, the caller's cold-miss
        answer.
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

        With the syft scanner disabled nothing is fetched. grype and trivy still
        read the harvested lockfiles, so for those of them that run (enabled in
        its section and kept by the run's scanner selection) each flagged
        package is named in a skip record, and a lockfile that cannot be read is
        named itself: a refused one as it is with syft on, and one that does not
        parse in a skip record that fails no gate, since nothing would have been
        fetched from it. With neither of them running there is nothing to name,
        and the tree is not walked.
        """
        config = getattr(self.context, "config", None)
        options = harvest_options_of(config)
        if not options["enabled"]:
            ASH_LOGGER.debug(
                "sdist lockfile harvest is disabled "
                "(scanners.syft.options.sdist_harvest.enabled)"
            )
            return []
        syft_off = not options["syft_enabled"]
        readers: List[str] = []
        if syft_off:
            readers = harvest_advisory_readers_that_run(
                config, getattr(self.context, "scanner_selection", None)
            )
            if not readers:
                ASH_LOGGER.debug(
                    "sdist lockfile harvest skipped: the syft scanner is disabled "
                    "(scanners.syft.enabled) and no scanner that reads the "
                    f"harvested lockfiles ({', '.join(HARVEST_ADVISORY_READERS)}) "
                    "runs"
                )
                return []
        lockfile_names = list(cast(Iterable[str], options["lockfiles"]))
        lock_files = self._lockfiles_in_scan_set(lockfile_names)
        if not lock_files:
            ASH_LOGGER.debug(
                f"No {', '.join(lockfile_names) or 'configured'} lockfiles in "
                f"{self.context.source_dir}; nothing to harvest"
            )
            return []

        ignore_paths = self._ignore_paths_skipping_harvest()
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

        results: List[Path] = []
        sources: Dict[Path, str] = {}
        if syft_off:
            readers_named = " and ".join(readers)

            def not_parsed(_lock_file: str, display: str, error: str) -> None:
                # Nothing would have been fetched from it, so it fails no gate: a
                # skip record with no limit, not a failed input.
                self.record_refused_input(
                    TreeInputRefused(
                        path=display,
                        reason=(
                            f"{HARVEST_SKIPPED_RULE}: {error}, so the packages it "
                            "pins are not named; the syft scanner is disabled "
                            "(scanners.syft.enabled), and the packages they embed "
                            f"are missing from the input of {readers_named}"
                        ),
                    )
                )

            for lock_file in lock_files:
                for package in self._flagged_in(lock_file, ignore_paths, not_parsed):
                    skip(package, self._unfetched_cause(package, readers_named))
        else:
            self._harvest(lock_files, ignore_paths, options, results, sources, skip)
        self._record_skips(skips, syft_off=syft_off)
        if sources:
            record_converted_sources(self.results_dir, self.context.work_dir, sources)
        return results

    def _flagged_in(
        self,
        lock_file: str,
        ignore_paths: List[IgnorePathWithReason],
        not_parsed: Callable[[str, str, str], None],
    ) -> List[FlaggedPackage]:
        """The flagged packages of one configured lockfile, or none.

        A directory or an ignored path gives none, an ignored one with a debug
        line. A lockfile the tree refuses to open is recorded as a refused input
        with no limit, whatever syft says: the tree's refusal is the same fact
        either way. One that does not parse as a uv lock is handed to
        ``not_parsed`` with its scan-set path, its display path and the parse
        error, which quotes none of its content; the caller decides how it counts.
        """
        if Path(lock_file).is_dir():
            return []
        ignored_by = self._ignored_by(lock_file, ignore_paths)
        if ignored_by is not None:
            ASH_LOGGER.debug(
                f"Skipping harvest of ignored path: {lock_file} due to "
                f"global ignore_path '{ignored_by.path}' with reason "
                f"'{ignored_by.reason}'",
                extra=NO_MARKUP,
            )
            return []
        try:
            handle = self.open_source_file(lock_file)
        except TreeInputRefused as refused:
            self.record_refused_input(refused)
            return []
        from automated_security_helper.utils.scanned_tree import relative_display

        display = relative_display(lock_file, self.context.source_dir)
        with handle:
            lock_bytes = handle.read()
        try:
            flagged = flagged_packages_in_uv_lock(lock_bytes, display)
        except ValueError as error:
            not_parsed(lock_file, display, str(error))
            return []
        if not flagged:
            ASH_LOGGER.debug(
                f"{display}: no resolved package names a platform wheel; "
                "nothing to harvest",
                extra=NO_MARKUP,
            )
        return flagged

    def _harvest(
        self,
        lock_files: List[str],
        ignore_paths: List[IgnorePathWithReason],
        options: Mapping[str, object],
        results: List[Path],
        sources: Dict[Path, str],
        skip: Callable[[FlaggedPackage, str], None],
    ) -> None:
        """Fetch, verify and materialize the flagged packages of ``lock_files``.

        The syft-on half of convert(), and the only part that sets anything up
        for a fetch: a cache root, a per-run staging directory when no
        persistent root is usable, and the results directory. A lockfile that
        does not parse is lost coverage here, since the harvest set out to
        fetch from it.
        """
        ecosystems = list(cast(Iterable[str], options["ecosystems"]))
        max_sdist_bytes = (
            int(cast(Union[int, str], options["max_sdist_mb"])) * 1024 * 1024
        )
        offline = is_offline_mode() or bool(options["syft_offline"])
        run_private_cache: Optional[tempfile.TemporaryDirectory] = None
        cache_root = self._cache_root(options["cache_dir"])
        if cache_root is None:
            # No usable persistent root (_cache_root said why): cache in a
            # private directory of this run alone, which no repository content
            # can pre-fill, and remove it with the run.
            run_private_cache = tempfile.TemporaryDirectory(prefix="ash-sdist-harvest-")
            cache_root = Path(run_private_cache.name)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        def not_parsed(lock_file: str, _display: str, error: str) -> None:
            self.record_failed_input(lock_file, error, kind="input")

        try:
            for lock_file in lock_files:
                for package in self._flagged_in(lock_file, ignore_paths, not_parsed):
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

    @staticmethod
    def _unfetched_cause(package: FlaggedPackage, readers_named: str) -> str:
        """Why a flagged package was not harvested while the syft scanner is off.

        A rejected entry, and one that pins no sdist by sha256, would not be
        fetched with syft on either, so each keeps the cause it has there.
        """
        if package.rejected_reason is not None:
            return package.rejected_reason
        if package.sdist_url is None or package.sdist_sha256 is None:
            return NO_SHA256_PIN_CAUSE
        return (
            "the syft scanner is disabled (scanners.syft.enabled), so its pinned "
            "sdist was not fetched and the packages it embeds are missing from "
            f"the input of {readers_named}"
        )

    def _record_skips(
        self, skips: Dict[str, List[Tuple[str, str]]], *, syft_off: bool
    ) -> None:
        """One ``ash-sbom-harvest-skipped`` record per cause, with no limit.

        With syft on the record names what the SBOM does not cover. With it off
        there is no SBOM, and the record names the packages not harvested.
        """
        for cause, entries in sorted(skips.items()):
            lock_display = entries[0][0]
            named = ", ".join(detail for _lock, detail in entries)
            covered = (
                f"not harvested: {named}"
                if syft_off
                else f"the SBOM does not cover the embedded lockfiles of: {named}"
            )
            self.record_refused_input(
                TreeInputRefused(
                    path=lock_display,
                    reason=f"{HARVEST_SKIPPED_RULE}: {cause}; {covered}",
                )
            )

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
        skip,
    ) -> None:
        """Harvest one flagged package, or record why it was skipped."""
        if package.rejected_reason is not None:
            skip(package, package.rejected_reason)
            return
        if package.sdist_url is None or package.sdist_sha256 is None:
            skip(package, NO_SHA256_PIN_CAUSE)
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
