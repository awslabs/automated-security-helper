# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
from contextlib import ExitStack
from datetime import datetime, timezone
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Annotated, Any, ClassVar, Iterable, List, Literal, Set

import yaml
from pydantic import Field, PrivateAttr

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    redacted_command_record,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Invocation,
    SarifReport,
)
from automated_security_helper.utils.display_text import escape_controls
from automated_security_helper.utils.get_scan_set import (
    file_links_leaving_tree,
    honors_ignore_files,
)
from automated_security_helper.base.uv_tool_mixin import guarded_values_read
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.get_shortest_name import get_shortest_name
from automated_security_helper.utils.link_exclusions import walked_files
from automated_security_helper.utils.sarif_utils import (
    attach_scanner_details,
    ignore_paths_for_locations,
)
from automated_security_helper.utils.scanned_tree import (
    REASON_LINK_LEAVES_TREE,
    TreeInputRefused,
    open_in_scanned_tree,
    relative_display,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
    find_executable,
    in_tree_refusal,
)

# snyk code test reads exclusions from files in the tree it tests, at any depth,
# and leaves the files they name out of the analysis. Its native implementation
# collects files named .snyk, .dcignore and .gitignore (code-client-go
# internal/commands/code_workflow/native_workflow.go, getFilesForPath); its
# legacy one globs *.snyk, *.dcignore and *.gitignore by base name
# (@snyk/code-client src/files.ts, collectFilePolicies). Neither has an option
# that turns this off: code test takes no --policy-path. A file named exactly
# .gitignore is left to snyk while ASH's own scan set honors it too
# (utils/get_scan_set.py); with honor_ignore_files false it is kept out of the
# copy and counts as an exclusion file (_stage_source, tree_exclusion_files).
_POLICY_SUFFIX = ".snyk"
_IGNORE_SUFFIXES = (".dcignore", ".gitignore")
_POLICY_SECTIONS = ("code", "global")
# A larger exclusion file is not parsed, and counts as excluding.
_MAX_EXCLUSION_FILE_BYTES = 1024 * 1024
_REFUSAL_FILES_SHOWN = 10


def tree_exclusion_files(
    target: Path, *, gitignore_excludes: bool = False
) -> List[Path]:
    """The files under ``target`` that would make snyk code test leave files out.

    A ``.snyk`` policy counts when its ``exclude.code`` or ``exclude.global`` has
    an entry, and an ignore file when it has a rule. One that is not a regular
    file inside the tree (snyk reads a link's target), cannot be read, or cannot
    be parsed counts too. ``.git`` is walked as well, as snyk's native filter
    walks it. A file named exactly ``.gitignore`` counts only with
    ``gitignore_excludes``: the scan set honors it too unless
    ``honor_ignore_files`` is false, and then the files it names are in the scan
    set while snyk would still leave them out.

    A link to a directory is not followed, and nothing behind it counts, because
    snyk does not follow one either. Its native filter lists files with Go's
    ``filepath.WalkDir`` (go-application-framework ``pkg/utils/file_filter.go``,
    ``GetAllFiles``), which reports a link to a directory as an entry and does not
    walk into it. Its legacy one globs with ``followSymbolicLinks`` set from
    ``symlinksEnabled`` (``@snyk/code-client`` ``collectFilePolicies``), which the
    CLI's ``snyk code test`` does not set (snyk/cli
    ``src/lib/plugins/sast/analysis.ts``). Measured on those sources as of
    2026-10-11.
    """
    found: List[Path] = []
    for directory, _subdirectories, names in os.walk(target):
        for name in names:
            if _is_exclusion_name(name, gitignore_excludes=gitignore_excludes):
                path = Path(directory) / name
                if _excludes(path, Path(target)):
                    found.append(path)
    return sorted(found)


def _is_exclusion_name(name: str, *, gitignore_excludes: bool = False) -> bool:
    if name.endswith(_POLICY_SUFFIX):
        return True
    if name == ".gitignore":
        return gitignore_excludes
    return name.endswith(_IGNORE_SUFFIXES)


def _excludes(path: Path, root: Path) -> bool:
    try:
        with open_in_scanned_tree(path, root) as handle:
            content = handle.read(_MAX_EXCLUSION_FILE_BYTES + 1)
    except (TreeInputRefused, OSError):
        return True
    if len(content) > _MAX_EXCLUSION_FILE_BYTES:
        return True
    text = content.decode("utf-8", errors="replace")
    if not path.name.endswith(_POLICY_SUFFIX):
        return any(
            line.strip() and not line.strip().startswith("#")
            for line in text.splitlines()
        )
    try:
        policy = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        # RecursionError: nesting deeper than the parser's stack. Unreadable as
        # a policy, so it counts, like any file that cannot be parsed.
        return True
    exclude = policy.get("exclude") if isinstance(policy, dict) else None
    return isinstance(exclude, dict) and any(
        exclude.get(section) for section in _POLICY_SECTIONS
    )


#: ``snyk code test`` exits 3 when the target holds no file it supports.
_NO_SUPPORTED_FILES_EXIT_CODE = 3


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" + ("" if number == 1 else "s")


def _copy_stream(source: Any, destination: Any) -> bool:
    """Copy ``source`` to ``destination``; True when reading the source failed.

    A failed read is the source's problem and skips the file; a failed write is
    raised to the caller.
    """
    while True:
        try:
            chunk = source.read(1024 * 1024)
        except OSError:
            return True
        if not chunk:
            return False
        destination.write(chunk)


#: The name every copy's directory under TMPDIR starts with, which is what a later
#: run's sweep matches on.
_COPY_PREFIX = "ash-snyk-code-"

#: How old an unheld copy has to be before a sweep removes it, when the scan has no
#: timeout to go by.
_UNBOUNDED_SWEEP_AGE_SECONDS = 3600


def _hold(directory: Path) -> int | None:
    """Lock ``directory`` for as long as this process keeps the returned descriptor.

    The kernel drops the lock when the process ends, however it ends, which is what
    tells a later run's sweep that the copy is abandoned. None where flock is not
    available (Windows) or the filesystem refuses it; such a copy is never swept.
    """
    try:
        import fcntl
    except ImportError:
        return None
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        # The directory cannot be opened for the lock (a filesystem that refuses
        # the open, a directory gone already): unlocked, like one flock refuses,
        # rather than raised out of _stage_source before the copy's removal is
        # registered, which left the directory behind.
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _scan_set_name(name: str) -> str:
    """A scan-set line as the path it names: without the one line ending a cached
    list leaves, and nothing more. ``rstrip`` took every trailing newline, so a file
    whose name ends in one was copied under a different name, or skipped."""
    return name.removesuffix("\n")


def _sweep_abandoned_copies(
    temp_root: Path, older_than: float, *, keep: Iterable[Path] = ()
) -> None:
    """Remove the copies a killed run left in ``temp_root``.

    The finally that removes a copy does not run when the process is killed (SIGKILL,
    or a SIGTERM with Python's default handling). A copy is removed here only when it
    is this user's, is a real directory whose name starts with ``_COPY_PREFIX``, was
    last modified more than ``older_than`` seconds ago, and no process holds its lock
    (``_hold``). Age alone would not do: a run copying a large tree, then testing it
    for up to the scan timeout, keeps a copy longer than either.

    A directory in ``keep``, or one holding a directory in ``keep``, is never removed
    whatever its name: the scan's own source and output directories can sit under
    TMPDIR with a name that starts like a copy's, and the name alone does not make
    them one.
    """
    try:
        import fcntl
    except ImportError:
        return
    kept = [Path(os.path.realpath(path)) for path in keep]
    now = time.time()
    try:
        entries = [e for e in os.scandir(temp_root) if e.name.startswith(_COPY_PREFIX)]
    except OSError:
        return
    for entry in entries:
        real = Path(os.path.realpath(entry.path))
        if any(real == held or real in held.parents for held in kept):
            continue
        try:
            fd = os.open(entry.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            # Not a directory, a symlink, already gone, or not readable by us.
            continue
        try:
            st = os.fstat(fd)
            if st.st_uid != os.getuid() or now - st.st_mtime < older_than:
                continue
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                continue
            shutil.rmtree(entry.path, ignore_errors=True)
        finally:
            os.close(fd)


def _sarif_result_count(document: Any) -> int:
    """How many results a parsed SARIF document holds, counting suppressed ones."""
    if not isinstance(document, dict):
        return 0
    return sum(
        len(run.get("results") or [])
        for run in document.get("runs") or []
        if isinstance(run, dict)
    )


class SnykCodeScannerConfigOptions(ScannerOptionsBase):
    honor_tree_exclusions: Annotated[
        bool,
        Field(
            description="Let snyk code test apply the exclusion files it finds in "
            "the scanned tree: the exclude.code and exclude.global entries of a "
            ".snyk file and the rules of a .dcignore file, which leave the files "
            "they name out of the analysis. snyk has no option that stops it "
            "reading them, so while this is false and the tree has one, snyk-code "
            f"does not run and its error names the files. {SET_BY_THE_OPERATOR}"
        ),
    ] = False


class SnykCodeScannerConfig(ScannerPluginConfigBase):
    """Configuration for the Snyk code scanner."""

    name: Literal["snyk-code"] = "snyk-code"
    enabled: bool = True
    options: Annotated[
        SnykCodeScannerConfigOptions,
        Field(description="Configure snyk-code"),
    ] = SnykCodeScannerConfigOptions()


@ash_scanner_plugin
class SnykCodeScanner(ScannerPluginBase[SnykCodeScannerConfig]):
    """Runs ``snyk code test`` and returns the SARIF it writes."""

    #: snyk-code runs the Snyk CLI, which uploads the source to Snyk. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = False

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        # The token file alone: configstore is shared with other npm tools' settings.
        read_paths=("~/.config/configstore/snyk.json",),
        env_prefixes=("SNYK_",),
        env_names=("SNYK_TOKEN",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    # src/cli/exit-codes.ts: 0 no issues, 1 issues found, 2 an error, 3 no supported
    # project detected.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}

    # How many files of the scan set the source copy left out (_stage_source), for
    # the exit-3 reading in scan(). Reset per target.
    _staged_refused: int = PrivateAttr(default=0)

    def model_post_init(self, context):
        if self.config is None:
            self.config = SnykCodeScannerConfig()
        self.command = "snyk"
        self.subcommands = ["code", "test"]
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(
            format_arg=None,
            format_arg_value=None,
            output_arg="--sarif-file-output",
            scan_path_arg=None,
            extra_args=[],
        )
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        """Validate scanner configuration.

        Returns:
            bool: True if validation passes
        """
        # TODO: Validate this is rejecting snyk with offline mode.
        if self._is_offline_mode():
            self._plugin_log(
                f"Offline mode detected. Skipping validation for {self.__class__.__name__}"
            )
            return False

        # Check if SNYK_TOKEN is defined on the environment variable or if using local
        # mode, the file ${HOME}/.config/configstore/snyk.json or ${HOME}/.config/configstore/.snyk.json exists
        if os.environ.get("SNYK_TOKEN", "") != "":
            # Token found in environment variable
            pass
        else:
            # Check for credential files
            home = Path.home()
            snyk_config_paths = home.joinpath(".config", "configstore", "snyk.json")

            if not snyk_config_paths.exists():
                # No credentials found
                self._plugin_log(
                    "Warning: No Snyk credentials found. SNYK_TOKEN env var is not set and no credential files found at ~/.config/configstore/snyk.json. The scan might fail.",
                    level=logging.WARNING,
                )

        snyk_binary = find_executable("snyk")
        if not snyk_binary or snyk_binary is None:
            # A copy found only inside the scanned tree was refused, not missing:
            # recorded as ScannerPluginBase.validate_plugin_dependencies records
            # it, so the MISSING row says so rather than "not found on PATH".
            refusal = in_tree_refusal("snyk")
            if refusal is not None:
                self.dependency_unavailable_reason = refusal
            return False
        return True

    def _process_config_options(self):
        # severity_threshold is not passed as --severity-threshold: snyk would drop
        # the findings below it before ASH saw them, so they would be neither
        # reported nor counted. ASH applies it after the scan, as for every
        # scanner, to the severity snyk gave each finding; the option says which
        # findings count as failures, not which are reported.
        return super()._process_config_options()

    def _resolve_arguments(
        self, target: Path, results_file: Path | None = None
    ) -> List[str]:
        """Resolve arguments for Snyk code test command.

        Args:
            target: Target to scan
            results_file: Path to results file

        Returns:
            List[str]: Arguments to pass to Snyk
        """
        # Process configuration options to populate extra_args
        self._process_config_options()

        # Start with base command and subcommands
        args = [self.command, *self.subcommands]

        # Add extra args. A value may be a number or a bool (ToolExtraArg), and
        # a spawn takes text only; a bool is spelled as a config file spells it,
        # the rule ScannerPluginBase._resolve_arguments applies, which this
        # override does not call.
        for tool_extra_arg in self.args.extra_args:
            args.append(tool_extra_arg.key)
            value = tool_extra_arg.value
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif value is not None and not isinstance(value, str):
                value = str(value)
            if value is not None:
                args.append(value)

        # Add target path
        args.append(Path(target).as_posix())

        # Add SARIF output argument with equal sign format (required by Snyk)
        if results_file is not None:
            args.append(f"--sarif-file-output={Path(results_file).as_posix()}")

        return args

    def _refuse_output_dir_inside(self, target: Path) -> None:
        """Refuse a target that holds ASH's own output directory.

        snyk would upload it with the rest: an earlier run's reports and logs,
        which can quote code from ignored paths, and the converted files. snyk
        honors a ``.gitignore``, and ASH writes one there, but that is read from
        snyk's sources and not measured, so it is not relied on: ASH's output is
        never in what snyk is given. With the default output directory,
        ``.ash/ash_output``, that refuses the source target; the converted target,
        the work directory below the output directory, is not affected.

        Raises:
            ScannerError: Naming the output directory and the remedy.
        """
        inside = self._output_dir_inside(Path(target))
        if inside is None:
            return
        raise ScannerError(
            f"Not running snyk code test on {Path(target).as_posix()}: ASH's output "
            f"directory '{escape_controls(inside.as_posix())}' is inside it, and "
            "snyk has no option that leaves out a path, so it would upload ASH's own "
            "output: an earlier run's reports and logs, and the converted files. "
            "Pass --output-dir with a directory outside the scanned tree to run "
            "snyk-code on it (snyk code test was not started)."
        )

    def _refuse_ignored_files(self, target: Path, ignore_paths: Any) -> None:
        """Refuse a target holding a file the global ignore paths ignore.

        ``snyk code test`` uploads the files it reads to Snyk and has no option
        that leaves out a path, so an ignored file would leave the host. The other
        scanners are told to leave such a file out, or ASH drops its findings; for
        an upload that is not enough. The files are every file snyk is given
        (``walked_files``, which walks as the tools do): the source directory for
        the source target, and the work directory, wherever it is, for the
        converted one. Each is matched exactly as ASH matches the location snyk
        reports for a finding in it, its path below the directory snyk tests
        (``sarif_utils.ignore_paths_for_locations``, the findings step's own
        matching). So a converted file is matched by its path below the work
        directory, not the source directory: a file whose findings ASH would drop
        is refused, and a file whose findings ASH keeps is not. The converters do
        not convert an ignored notebook or archive in the first place, and a
        converted file's name is flattened, so an exact source path such as
        ``vendor/nb.ipynb`` is kept from snyk by that skip, not by this match.

        The ignore paths are the operator's: the default config sets none, and
        the scanner-level default exclusions (``KNOWN_IGNORE_PATHS``) are not
        ignore paths. snyk-code has no exclusion option of its own to check as
        well; a test fails if it gains one.

        Raises:
            ScannerError: Naming the first ignored file and the pattern that
                matched it, with the number of ignored files, the patterns and the
                remedy. snyk is then not run on ``target``.
        """
        if not ignore_paths:
            return
        if self.context is None:
            # Never the case for a scan the executor runs; refused rather than
            # run unchecked.
            raise ScannerError(
                "Not running snyk code test: there is no scan context to match "
                "global_settings.ignore_paths against (snyk code test was not started)."
            )
        files, _ = walked_files(target)
        root = Path(target)
        found = ignore_paths_for_locations(files, self.context, ignore_paths)
        if not found:
            return
        # walked_files sorts, and ignore_paths_for_locations keeps that order.
        ignored = {relative: matched.path for relative, matched in found.items()}
        first_path, first_pattern = next(iter(ignored.items()))
        patterns = list(dict.fromkeys(ignored.values()))
        shown = ", ".join(repr(pattern) for pattern in patterns[:3])
        if len(patterns) > 3:
            shown += f" and {len(patterns) - 3} more"
        count = len(ignored)
        raise ScannerError(
            f"Not running snyk code test on {root.as_posix()}: {count} "
            f"{'file' if count == 1 else 'files'} there "
            f"{'is' if count == 1 else 'are'} in global_settings.ignore_paths "
            f"({shown}), the first '{escape_controls(first_path)}', "
            f"which {first_pattern!r} matches. snyk has no option that leaves out a "
            f"path, so it would upload {'it' if count == 1 else 'them'}. To scan the "
            "rest, narrow ignore_paths, or leave snyk-code out with "
            "--exclude-scanners snyk-code (snyk code test was not started)."
        )

    def _refuse_links_leaving(self, target: Path) -> None:
        """Refuse a target holding any link whose target leaves it.

        ``snyk code test`` uploads the files it reads to Snyk, has no option that
        leaves out one path (``--exclude`` is for open-source projects, and takes
        names, not paths), and how it treats links has not been measured by running
        it. So a link the repository committed could send a file from outside the
        scanned tree, such as a credentials file, off the host. A link to a
        directory (``creds -> ~/.aws``) counts too: snyk's sources list files
        without walking into one (see ``tree_exclusion_files``), but that is read,
        not measured, and the files below one could be every credential the host
        has. The links come
        from ``file_links_leaving_tree``, which does not read ignore files and lists
        the directory links it does not enter.

        Raises:
            ScannerError: Naming the first such link. snyk is then not run on
                ``target``.
        """
        directory_links: List[str] = []
        links = sorted(
            file_links_leaving_tree(target, directory_links=directory_links)
            + directory_links
        )
        if links:
            raise ScannerError(
                f"Not running snyk code test on {Path(target).as_posix()}: "
                f"{links[0]!r}: {REASON_LINK_LEAVES_TREE}, and snyk has no option "
                "that leaves out one path, so it might upload the file it points at."
            )

    def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
        """Abstract stub — SnykCodeScanner overrides scan() directly; this is unreachable."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[Any] | None = None,
        config: Any | None = None,
        *args,
        **kwargs,
    ) -> SarifReport | bool | None:
        """Run ``snyk code test`` on the target and return its SARIF report.

        Neither target is run when it holds ASH's output directory, a link that
        leaves it, or a file ``global_ignore_paths`` matches (the ``_refuse_*``
        methods below). For the source target, snyk then tests a copy of the scan
        set that leaves out ``global_ignore_paths`` (see :meth:`_stage_source`), so
        what ASH excludes is not sent to Snyk.

        Args:
            target: Target file or directory to scan
            target_type: Type of target (source or converted)
            global_ignore_paths: ``global_settings.ignore_paths``
            config: Scanner configuration

        Returns:
            The SarifReport Snyk wrote; True for an empty target; False when snyk
            cannot run; None when Snyk wrote no readable SARIF.
        """
        # No claim until this target's run makes one (exit 3 below), so the count
        # from an earlier target is never read as this one's. The exit code too:
        # _run_subprocess keeps the worst code of every run of this instance, and the
        # executor runs one instance over the source tree and then the converted one,
        # so after a source that exited 3 the converted target read 3 whatever its
        # own run returned, and was graded SKIPPED with its findings unread. And
        # the tool lines: a failed converted-target run otherwise records the
        # source target's stderr as its own (exitCodeDescription, the failure text).
        self.targets_attempted = None
        self.targets_failed = 0
        self.exit_code = 0
        self.output = []
        self._reset_errors()
        self._staged_refused = 0
        # Check if the target directory is empty or doesn't exist
        if _target_is_empty(target):
            message = (
                f"Target directory {target} is empty or doesn't exist. Skipping scan."
            )
            self._plugin_log(
                message,
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            # No tool runs for this target, so its record starts and ends now: a
            # start time left from the previous target would give it that
            # target's duration.
            self.start_time = None
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return True

        validated = self._pre_scan(
            target=target,
            target_type=target_type,
            config=config,
        )
        if not validated:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        if not self.dependencies_satisfied:
            self._post_scan(
                target=target,
                target_type=target_type,
            )
            return False

        honor_gitignore = honors_ignore_files(getattr(self.context, "config", None))
        if not self.config.options.honor_tree_exclusions and target_type != "source":
            # The converted target is tested where ASH wrote it, so the exclusion
            # files there are the ones snyk reads. The source target is tested as
            # a copy of the scan set and is checked once the copy exists (below):
            # a file outside the scan set (.git, an ignored directory, ASH's
            # output) never reaches snyk, so it excludes nothing. A .gitignore
            # counts when the scan set does not honor it, since then the files it
            # names are tested by ASH and would be left out by snyk.
            excluding = tree_exclusion_files(
                Path(target), gitignore_excludes=not honor_gitignore
            )
            if excluding:
                raise ScannerError(self._exclusion_refusal(excluding, Path(target)))

        # snyk has no option that leaves out a path, so before anything is copied or
        # sent, for either target, it is not given a directory that holds ASH's own
        # output directory, a link leaving it, or a file the operator's ignore paths
        # match. The copy of the source target leaves the same files out as a second
        # guard; the converted target is tested where ASH wrote it, so these refusals
        # are the only guard it has.
        # No exit code until snyk returns one, as the template's scan() has it: a
        # target refused before the tool starts reports no exit code, not the 0
        # set above. The refusals below are the first such path.
        self.exit_code = None
        try:
            self._refuse_output_dir_inside(Path(target))
            self._refuse_links_leaving(Path(target))
            self._refuse_ignored_files(Path(target), global_ignore_paths)
        except ScannerError:
            # The run is over for this target as much as for one that failed: the
            # executor records end_time, and one left from the previous target
            # would give this one an end before its start. These refusals ran
            # ahead of the handler below that resets it, so a converted target
            # refused after the source target ran kept the source's end time.
            self.end_time = datetime.now(timezone.utc)
            raise

        try:
            # Undone in the finally: the copy snyk tests for the source target, and
            # the sandbox's read grant for it.
            cleanup = ExitStack()
            target_results_dir = self.results_dir.joinpath(target_type)
            results_file = target_results_dir.joinpath("results_sarif.sarif")
            target_results_dir.mkdir(exist_ok=True, parents=True)
            # A report left by an earlier run must not be read as this run's: snyk
            # writes none when it fails, and the read below takes whatever is here.
            results_file.unlink(missing_ok=True)

            tested = target
            if target_type == "source":
                staged = self._stage_source(target, global_ignore_paths or [], cleanup)
                if staged is None:
                    # _stage_source has said why: every file is left out, or there
                    # is none. Nothing was evaluated, so the row grades SKIPPED,
                    # not PASSED with exit code 0 for a tool that never ran.
                    self.targets_attempted = 0
                    self._post_scan(target=target, target_type=target_type)
                    return True
                if not self.config.options.honor_tree_exclusions:
                    # The copy holds exactly the files snyk is given, so an
                    # exclusion file counts here only when it reaches snyk. A
                    # .gitignore in the copy was honored by the scan set already
                    # (when it is not honored, _stage_source leaves it out).
                    excluding = tree_exclusion_files(staged)
                    if excluding:
                        raise ScannerError(self._exclusion_refusal(excluding, staged))
                tested = staged

            final_args = self._resolve_arguments(
                target=tested, results_file=results_file
            )
            # What the SARIF records: the directory that was scanned, not the copy
            # that is deleted when the run ends.
            reported_args = [
                Path(target).as_posix() if arg == Path(tested).as_posix() else arg
                for arg in final_args
            ]

            # The values hook is overridable and is read once, guarded, for the
            # log line and both SARIF records. When it raised or gave no usable
            # answer nothing can be redacted, so every record carries only the
            # command's name.
            read = guarded_values_read(self)
            redact_values = read.values
            if redact_values is None:
                shown_command = str(self.command)
                recorded_command_line = shown_command
                recorded_attach_line = shown_command
                recorded_arguments: List[str] = []
                self._plugin_log(
                    f"Running command: {shown_command} (the arguments are not "
                    f"shown: the plugin's values hook {read.failure()})",
                    target_type=target_type,
                    level=logging.VERBOSE,
                )
            else:
                recorded_command_line, recorded_arguments = redacted_command_record(
                    reported_args, redact_values
                )
                recorded_attach_line = recorded_command_line
                self._plugin_log(
                    "Running command: "
                    f"{text_without_values(' '.join(final_args), redact_values)}",
                    target_type=target_type,
                    level=logging.VERBOSE,
                )

            # No environment modifications are currently needed for Snyk Code.
            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=target_results_dir,
                timeout=effective_timeout,
            )
            # The run is over: its end time is recorded here, before the invocation
            # below reads it, so the first target's record carries this run's end
            # rather than None and the second's rather than the first's.
            self._post_scan(target=target, target_type=target_type)
            # A run the subprocess layer flagged (timed out, could not start, its
            # output not recorded, ended by a foreign signal) is refused before its
            # file is read, whatever exit code it carries.
            self._refuse_flagged_response(response, effective_timeout)

            # snyk exits 1 when it found issues, which is a completed scan, 2 when it
            # failed, and 3 when it found no supported project; see success_exit_codes.
            self._record_target_exit_code(response)
            # Exit 3 is snyk's "no supported projects detected": the target holds no
            # file Snyk Code reads, so it evaluated nothing. SKIPPED, by design,
            # rather than the ERROR every other code outside
            # success_exit_codes gets: a Terraform-only tree is not a failed scan.
            # targets_attempted = 0 is what the executor grades SKIPPED. Exit 2 is
            # still a failure.
            if self.exit_code == _NO_SUPPORTED_FILES_EXIT_CODE:
                if self._staged_refused:
                    # Not SKIPPED: files in the scan set were refused from the copy
                    # (_stage_source), so snyk may have been given none of the
                    # supported files the tree holds. Those files were not judged,
                    # and a SKIPPED row would read as "nothing here to scan".
                    self._plugin_log(
                        f"Snyk Code found no supported files in the copy of {target}, "
                        f"but {_count(self._staged_refused, 'file')} of the scan set "
                        "could not be copied for it (snyk exit code 3): the files it "
                        "was not given were not judged, so the target is failed.",
                        target_type=target_type,
                        level=logging.WARNING,
                    )
                    self.targets_attempted = 1
                    self.targets_failed = 1
                    return True
                self._plugin_log(
                    f"Snyk Code found no supported files in {target}; nothing was "
                    "evaluated (snyk exit code 3).",
                    target_type=target_type,
                    level=logging.INFO,
                )
                self.targets_attempted = 0
                return True

            if not self._exit_code_accepted():
                raise ScannerError(
                    f"Snyk scan failed with exit code {self.exit_code}: {self.errors}"
                )

            # SARIF mode - parse SARIF results
            if Path(results_file).exists():
                with open(results_file, mode="r", encoding="utf-8") as f:
                    scanner_results = json.load(f)
                # Snyk exits 1 only when it found issues, so a run that exits 1 and
                # reports none has not shown what it scanned: not a clean scan.
                if self.exit_code == 1 and not _sarif_result_count(scanner_results):
                    raise ScannerError(
                        "snyk exited with exit code 1, which it uses for issues "
                        f"found, but its SARIF file holds no results: {results_file}"
                    )
                try:
                    sarif_report: SarifReport = SarifReport.model_validate(
                        scanner_results
                    )

                    # Attach scanner details for proper identification
                    sarif_report = attach_scanner_details(
                        sarif_report=sarif_report,
                        scanner_name=self.config.name,
                        scanner_version=getattr(self, "tool_version", None),
                        invocation_details={
                            "command_line": recorded_attach_line,
                            "arguments": recorded_arguments,
                            "working_directory": get_shortest_name(input=target),
                            "start_time": self.start_time.isoformat()
                            if self.start_time
                            else None,
                            "end_time": self.end_time.isoformat()
                            if self.end_time
                            else None,
                            "exit_code": self.exit_code,
                        },
                    )

                    if sarif_report.runs:
                        sarif_report.runs[0].invocations = [
                            Invocation(
                                commandLine=recorded_command_line,
                                arguments=recorded_arguments,
                                startTimeUtc=self.start_time,
                                endTimeUtc=self.end_time,
                                executionSuccessful=self._exit_code_accepted(),
                                exitCode=self.exit_code,
                                exitCodeDescription="\n".join(self.errors),
                                workingDirectory=ArtifactLocation(
                                    uri=get_shortest_name(input=target),
                                ),
                            )
                        ]
                    return sarif_report
                except Exception as e:
                    self._plugin_log(
                        f"Failed to parse {self.__class__.__name__} results as SARIF: {str(e)}",
                        target_type=target_type,
                        level=logging.ERROR,
                        append_to_stream="stderr",
                    )
                    return
            else:
                self._plugin_log(
                    f"No results file found at {results_file}",
                    target_type=target_type,
                    level=logging.WARNING,
                    append_to_stream="stderr",
                )

        except Exception as e:
            # The run is over for this target, however it ended: the executor
            # records end_time, and one left from the previous target would give
            # this one an end before its start.
            self.end_time = datetime.now(timezone.utc)
            raise ScannerError(f"Snyk Code scan failed: {str(e)}")
        finally:
            cleanup.close()

    def _refuse_flagged_response(self, response: Any, timeout: float | None) -> None:
        """Raise for a run the subprocess layer flagged, before its file is read.

        The four readings ``ScannerPluginBase.scan`` makes for every template
        scanner, which this override of ``scan()`` left out: a killed tool writes
        no results file, so the error would otherwise be "No such file or
        directory" instead of the timeout; a tool that could not start the same; a
        tool that ran while ASH could not record its output (exit 0, a file that
        may be complete) is not graded on that file; a tool a signal ASH did not
        send ended did not finish. The exit code alone does not say any of this: a
        flagged response keeps the tool's own code, 0 included.
        """
        if not isinstance(response, dict):
            return
        name = self.__class__.__name__
        if response.get("timed_out"):
            limit = self._timeout_limit_token(timeout)
            if self.scan_could_not_stop is not None:
                ending = f"{COULD_NOT_STOP_ENDING}. It produced no"
            else:
                ending = f"{WAS_KILLED_ENDING}, so it produced no"
            raise ScannerError(
                text_without_values(
                    f"{name} timed out after {limit}{ending} results file. Raise "
                    f"scanners.{getattr(self.config, 'name', '<scanner>')}.options"
                    ".scan_timeout if this target legitimately needs longer, or set "
                    "it to null to leave this scanner unbounded.",
                    self._values_to_redact(),
                )
            )
        if response.get("spawn_failed"):
            raise ScannerError(
                f"{name} could not start its tool, so it produced no results file."
            )
        if response.get("post_run_error"):
            raise ScannerError(
                text_without_values(
                    f"{name} ran, but ASH could not record the scanner's output: "
                    f"{response.get('error')}",
                    self._values_to_redact(),
                )
            )
        if response.get("signaled"):
            raise ScannerError(
                text_without_values(
                    f"{name} did not finish: {response.get('error')}",
                    self._values_to_redact(),
                )
            )

    @staticmethod
    def _exclusion_refusal(files: List[Path], target: Path) -> str:
        shown = [
            relative_display(path, target) for path in files[:_REFUSAL_FILES_SHOWN]
        ]
        more = len(files) - len(shown)
        listed = ", ".join(shown) + (f" and {more} more" if more else "")
        return (
            f"snyk-code did not run: snyk code test would leave out the files that "
            f"{listed} in the scanned tree exclude, and it has no option that stops "
            "it reading them. Remove them, or accept them with --config-overrides "
            "scanners.snyk-code.options.honor_tree_exclusions=true."
        )

    def _stage_source(
        self, target: Path, ignore_paths: List[Any], cleanup: ExitStack
    ) -> Path | None:
        """Copy the scan set under ``target`` to a temporary directory, less ignores.

        ``snyk code test`` takes no option that excludes a path: its only exclusion
        mechanism is a ``.snyk`` file inside the directory it tests, and ASH does
        not write into the scanned repository. Testing a copy is how an ignore
        path, a ``.gitignore`` or ``.ignore`` entry or ASH's own output directory
        inside the tree stays off Snyk's servers, for every pattern ASH accepts,
        matched the way ASH matches findings against ignore paths. Each file is
        read through ``open_in_scanned_tree``, so a symlink, a file with a second
        hard link or a path outside the tree is not copied, and so not sent; such a
        file is skipped and counted.

        The copy is made in a new directory under the system temporary directory,
        outside the scanned tree and the output directory: other scanners walking
        the tree while snyk runs do not see it, and an output directory uploaded
        after a killed run does not carry a copy of the source. ``cleanup`` removes
        it, and under a sandbox also holds the grant that lets snyk read it. A
        killed run skips that, so each run first removes the copies killed runs
        left (``_sweep_abandoned_copies``) and holds a lock on its own.

        Raises:
            ScannerError: The copy could not be written (a full disk, say), or every
                file that would have been sent was refused. Snyk would otherwise
                test part of the tree, or nothing, and report a complete scan.

        Returns:
            The copy, or None when no file is left to send: every file is under an
            ignore path or in ASH's output directory, or the scan set holds none.
            Which of these it was is logged.
        """
        import dataclasses
        import tempfile

        from automated_security_helper.utils.get_scan_set import scan_set
        from automated_security_helper.utils.sandbox.fs_guard import (
            open_for_write_bytes,
        )
        from automated_security_helper.utils.sandbox.scope import (
            SandboxScope,
            active_scope,
            sandbox_scope,
        )
        from automated_security_helper.utils.scanned_tree import (
            TreeInputRefused,
            open_in_scanned_tree,
        )
        from automated_security_helper.utils.suppression_matcher import (
            ignore_path_matches,
        )

        root = Path(target)
        temp_root = Path(os.path.realpath(tempfile.gettempdir()))
        for name, directory in (
            ("scanned directory", root),
            ("output directory", Path(self.context.output_dir)),
        ):
            real = Path(os.path.realpath(directory))
            if temp_root == real or real in temp_root.parents:
                raise ScannerError(
                    f"snyk-code makes its copy of the scan set under the temporary "
                    f"directory {temp_root}, which is inside the {name}. Set TMPDIR "
                    "to a directory outside both."
                )
        _sweep_abandoned_copies(
            temp_root,
            older_than=self._effective_scan_timeout() or _UNBOUNDED_SWEEP_AGE_SECONDS,
            # Never the scan's own directories, whatever they are named.
            keep=(root, Path(self.context.output_dir)),
        )
        staged = Path(tempfile.mkdtemp(prefix=_COPY_PREFIX))
        # Registered first, so it is released last: the copy is removed while the
        # lock still says it is in use.
        held = _hold(staged)
        if held is not None:
            cleanup.callback(os.close, held)
        cleanup.callback(shutil.rmtree, staged, ignore_errors=True)
        # ASH's own output is not tested for here: the scan set already leaves it
        # out, keeping only the files git tracks in ASH's output directories
        # (utils/scan_output_dirs.py). Those are the repository's own files, and
        # a repository must not be able to hide one from Snyk by committing it
        # under the output directory, as a test here that left out every file
        # under the output directory let it do.
        copied = ignored = refused = 0
        honor_gitignore = honors_ignore_files(getattr(self.context, "config", None))

        def _not_copied(shown: object, why: object) -> None:
            # Logged, and recorded: snyk never evaluates a file left out here, so
            # a run that goes on grades ERROR naming it, not PASSED over it
            # (PluginBase.unevaluated_targets).
            self._plugin_log(
                f"{shown} not copied for Snyk: {why}",
                target_type="source",
                level=logging.DEBUG,
            )
            self.record_unevaluated_target(shown)

        # The same rules the run's own scan set was built under, so a copy built
        # when the run's list is not read back leaves out what that list left out:
        # the ignore files as the config says, and the workspace's output directory.
        # The switch is read from the config at the call, the shape every scan-set
        # consumer passes (tests/unit/utils/test_scan_set_ignore_file_switch.py).
        # A link open_in_scanned_tree refuses is judged after the loop, against the
        # files the copy actually holds (copied_names): a link to a copied file is
        # tested under that file's own name (_aliased_in_copy); a link to a file an
        # ignore path or the .gitignore skip left out of the copy is not.
        copied_names: Set[str] = set()
        deferred_links: List[tuple[Path, Path, str]] = []
        for name in scan_set(
            source=str(root),
            output=str(self.context.output_dir),
            honor_ignore_files=honors_ignore_files(
                getattr(self.context, "config", None)
            ),
            run_id=getattr(self.context, "run_id", None),
            workspace_output_dir=getattr(self.context, "workspace_output_dir", None),
        ):
            # Only the line ending a cached list leaves: "a.js " is its own file,
            # and so is a name that ends in a newline (_scan_set_name).
            path = Path(_scan_set_name(name))
            try:
                relative = path.relative_to(root)
            except ValueError:
                _not_copied(path.as_posix(), "it is outside the scanned directory")
                refused += 1
                continue
            if any(
                ignore_path_matches(relative.as_posix(), getattr(entry, "path", entry))
                for entry in ignore_paths
            ):
                ignored += 1
                continue
            if not honor_gitignore and path.name == ".gitignore":
                # snyk applies a .gitignore it finds in the copy and has no option
                # not to. The scan set does not honor it here, so the files it
                # names are in the copy and are to be tested; the file itself is
                # not something snyk code test reads.
                self._plugin_log(
                    f"{relative.as_posix()} not copied for Snyk: honor_ignore_files "
                    "is false, and snyk would apply it to the copy",
                    target_type="source",
                    level=logging.DEBUG,
                )
                continue
            # Reading the source may fail for one file (refused, unreadable), which
            # skips it. Writing the copy may not: a write that fails, a full disk
            # for one, would leave Snyk testing part of the tree as if it were all.
            # A link is never followed or copied as a link: open_in_scanned_tree
            # refuses the file when it, or any directory between it and the root, is
            # a symlink, so nothing it leads to reaches the copy.
            try:
                source = open_in_scanned_tree(path, root)
            except TreeInputRefused as refusal:
                # Judged after the loop: the file this may be a link to can come
                # later in the set, and whether it was copied is what decides.
                deferred_links.append((path, relative, refusal.reason))
                continue
            except OSError as error:
                _not_copied(relative.as_posix(), error)
                refused += 1
                continue
            destination = staged.joinpath(relative)
            with source:
                try:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with open_for_write_bytes(destination) as copy:
                        unreadable = _copy_stream(source, copy)
                except OSError as error:
                    raise ScannerError(
                        f"snyk-code could not write its copy of the scan set "
                        f"({error}), so Snyk was not run on a partial tree"
                    ) from error
            if unreadable:
                destination.unlink(missing_ok=True)
                _not_copied(relative.as_posix(), "it could not be read")
                refused += 1
                continue
            copied += 1
            copied_names.add(relative.as_posix())

        for path, relative, reason in deferred_links:
            tested_as = _aliased_in_copy(path, root, copied_names)
            if tested_as is not None:
                # A link to a file the copy holds: not copied itself (a link is
                # never followed into the copy), but snyk evaluates its content
                # under the target's own name, so it is not an unevaluated target
                # and does not count as refused.
                self._plugin_log(
                    f"{relative.as_posix()} not copied for Snyk: {reason}; it is "
                    f"tested as {tested_as}",
                    target_type="source",
                    level=logging.DEBUG,
                )
                continue
            _not_copied(relative.as_posix(), reason)
            refused += 1

        refused_reasons = (
            "a symlink, a file with a second hard link, a path outside the scanned "
            "tree, or unreadable"
        )
        # Read by scan() when snyk reports no supported file: a copy that lacks
        # files the scan set holds is not a tree with nothing to scan.
        self._staged_refused = refused
        if refused:
            self._plugin_log(
                f"{_count(refused, 'file')} in the scan set not copied "
                f"({refused_reasons}), so Snyk does not test them.",
                target_type="source",
                level=logging.WARNING,
            )
        if not copied:
            if refused:
                raise ScannerError(
                    f"snyk-code did not run: none of the files it would have sent to "
                    f"Snyk could be copied ({_count(refused, 'file')} refused: "
                    f"{refused_reasons})"
                )
            self._plugin_log(
                "Every file in the scan set is under an ignore path, so nothing is "
                "sent to Snyk."
                if ignored
                else "The scan set holds no file to send to Snyk, so nothing is sent.",
                target_type="source",
                level=logging.INFO,
            )
            return None

        self._plugin_log(
            f"Testing a copy of {_count(copied, 'file')} from the scan set; "
            f"{_count(ignored, 'file')} under ignore paths not sent to Snyk.",
            target_type="source",
            level=logging.INFO,
        )

        scope = active_scope()
        if isinstance(scope, SandboxScope):
            # Under a sandbox, snyk may read its scan target; make that the copy.
            cleanup.enter_context(
                sandbox_scope(dataclasses.replace(scope, scan_target=staged))
            )
        return staged


def _aliased_in_copy(path: Path, root: Path, copied: Set[str]) -> str | None:
    """The copied file's name that *path*, a link in the tree, resolves to; else None.

    *copied* holds the names, relative to *root*, of the files the copy holds. A
    file is an alias only when a link on its path (the file itself, or a directory
    between it and the root) resolves, as the filesystem resolves it
    (``os.path.realpath``), to a regular file inside *root* that was copied: snyk
    tests that content under the target's name. A file refused for another reason
    (a second hard link, not a regular file) resolves to its own name and is no
    alias; a link whose target is outside the tree, or inside it but left out of
    the copy (not in the scan set, under an ignore path, the .gitignore the copy
    leaves out), resolves to a name the copy does not hold and is no alias either.
    """
    try:
        own = path.relative_to(root)
        resolved = Path(os.path.realpath(path))
        target = resolved.relative_to(Path(os.path.realpath(root)))
    except (OSError, ValueError):
        return None
    if target == own:
        return None
    name = target.as_posix()
    if name not in copied:
        return None
    try:
        if not resolved.is_file():
            return None
    except OSError:
        return None
    return name


def _target_is_empty(target: Path) -> bool:
    """Whether ``target`` is missing, or a directory with nothing in it.

    A target that is a file is not empty, and a directory that cannot be listed
    is left to the tool: the probe used to raise ``NotADirectoryError`` or
    ``PermissionError`` out of ``scan()`` before its error handling began.
    """
    try:
        if not target.exists():
            return True
        return target.is_dir() and not any(target.iterdir())
    except OSError:
        return False
