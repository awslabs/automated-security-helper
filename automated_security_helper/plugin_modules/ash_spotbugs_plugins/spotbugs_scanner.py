# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SpotBugs with the Find Security Bugs plugin: JVM bytecode SAST as a community plugin.

What it runs
------------
``spotbugs -textui`` over the compiled JVM code (``.class`` files and ``.jar``,
``.war`` and ``.ear`` archives) in the scan target. SpotBugs analyses bytecode, not
source, so a tree of ``.java`` files alone has nothing for it to read. The scanner
then does nothing and says so at INFO: a clean skip, not a failure and not a
finding. ASH does not compile anything for it.

Find Security Bugs (``com.h3xstream.findsecbugs``) is a SpotBugs plugin that adds
the security detectors (injection, XXE, deserialization, weak crypto, path
traversal and so on). It is loaded from the ``plugin`` directory of the SpotBugs
installation, which ``install_pinned_spotbugs`` fills. A run whose SARIF does not
list it among ``tool.extensions`` fails: the scan would otherwise report a pass
with the security detectors missing.

SpotBugs is LGPL-2.1 and Find Security Bugs is LGPL-3.0. Both run as a separate
process the plugin starts; nothing of them is imported or bundled in ASH.

Invocation
----------
Measured on SpotBugs 4.10.5 with Find Security Bugs 1.14.0 (2026-11-19). Each flag
below was run against real class files and the output read back.

* ``-textui``: the command-line interface. The ``spotbugs`` script in ``bin/`` starts
  ``java`` from ``JAVA_HOME`` or ``PATH``.
* ``-sarif=<file>``: writes SARIF 2.1.0 to ``<file>``. The ``=`` form is the one the
  SpotBugs documentation gives ("Produce the bug reports in SARIF 2.1.0",
  https://spotbugs.readthedocs.io/en/stable/running.html).
* ``-exitcode``: without it SpotBugs exits 0 whatever it finds. With it the exit
  status is a bit set (``ExitCodes.java``): 1 bugs found, 2 classes needed for the
  analysis were missing, 4 serious analysis errors. Measured: 0 for a clean jar, 3
  (bugs and missing classes) for a jar with findings, 4 for an input that could not
  be opened, with no SARIF written. 0 to 3 are success, 4 and above fail the scan.
* ``-low`` / ``-medium`` / ``-high``: the confidence threshold (``confidence``
  option; the SpotBugs default and this plugin's is ``-medium``).
* ``-effort:<level>``: analysis effort (``effort`` option, default ``default``).
* The inputs are absolute paths after the options: class directories (the directory
  that holds the package root, found by reading each class file's own name) and
  archives. SpotBugs has no ``--`` separator, and an absolute path cannot be read
  as an option. The working directory is the source directory.

Nothing is passed that reads the scanned tree's configuration (no ``-include``,
``-exclude`` or ``-excludeBugs`` filter file, no ``-userPrefs``) or reaches the
network. No option takes a path from the scanned tree, so none is operator-only.

Which files it is handed
------------------------
``discover_jvm_inputs`` walks the target without following any link, and skips ASH's
own output directories. Archives are passed as they are. For class files it passes
the class root: SpotBugs needs the directory that holds ``org/``, not the file, and
the root is the class file's path minus the package path in its own constant pool.
Libraries kept in the tree (a ``lib/`` directory of jars) are therefore analysed as
application code, and their findings are reported; ``-auxclasspath`` is not used.

Severity
--------
SpotBugs writes a SARIF ``level`` per result from the bug rank: ``error`` for the
scary and scariest ranks, ``warning`` for troubling, ``note`` for of-concern
(``Level.fromBugRank``). The plugin keeps that level and sets ``issue_severity`` to
agree with it:

* ``error`` -> HIGH
* ``warning`` -> MEDIUM
* ``note`` -> LOW
* ``none`` -> INFO

``error`` is HIGH and not CRITICAL: a SpotBugs finding is a code pattern, not a
confirmed exploitable path. A result with no level is MEDIUM (the SARIF default); a
level not in the table is HIGH, so nothing is under-reported.

By default only results whose rule carries the ``SECURITY`` category are kept
(``security_only``). SpotBugs's own non-security detectors (style, performance,
bad practice, multithreading) are about code quality and, in a measured run over
one library, outnumbered the security results about twenty to one (528 results,
25 of them security). Turn ``security_only`` off
to keep them.

Report locations
----------------
SpotBugs writes source-style paths (``org/dom4j/DocumentFactory.java``), not the
path of the class file or the archive it read, and not the path in the repository.
When exactly one source file in the target ends with that path, the result's URI is
rewritten to it, so path suppressions and reports point at a real file. Otherwise
the path is left as SpotBugs wrote it.

Suppressions
------------
ASH suppressions (rule id, path, line) apply to the SARIF. SpotBugs's own
``@SuppressFBWarnings`` annotation is honored by SpotBugs inside the bytecode and
cannot be turned off by this plugin.

Exit status and output
----------------------
A run that exits 4 or more fails the scan even when a report is on disk. A stale
report is deleted before each run. The tool's stderr is kept in its log file;
SpotBugs writes class names there, which come from the scanned tree.

Offline
-------
SpotBugs and the plugin are installed from pinned release files and read no
network at scan time (``OfflineStrategy.BUNDLED``).

Sandbox
-------
The strict default, ``SandboxRequirements()``. Whether the JVM starts under it with
only the baseline environment (``JAVA_HOME`` is not passed) was not measured; see
the plugin README.
"""

from __future__ import annotations

import logging
import os
import shutil
import struct
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import CustomCommand
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    NO_BIN_DIRECTORY,
    current_bin_path,
    download_file,
    refusing_install_command,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The pinned releases. Both files are published for every platform: SpotBugs is a
#: tree of jars and a shell script, so there is no per-platform asset.
SPOTBUGS_VERSION = "4.10.5"
FINDSECBUGS_VERSION = "1.14.0"
SPOTBUGS_URL = (
    "https://github.com/spotbugs/spotbugs/releases/download/"
    f"{SPOTBUGS_VERSION}/spotbugs-{SPOTBUGS_VERSION}.tgz"
)
FINDSECBUGS_URL = (
    "https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/"
    f"{FINDSECBUGS_VERSION}/findsecbugs-plugin-{FINDSECBUGS_VERSION}.jar"
)
#: SHA256 of the two release files, computed from the downloads of 2026-11-19.
SPOTBUGS_SHA256 = "cce3244900cc215ccd9f5a8db29ed9468fc47824faf662f4fad005343d96007e"  # pragma: allowlist secret
FINDSECBUGS_SHA256 = "6fa340344fa433ff46c2985dab1010e8bc739f9395c983594a5240095e92abc8"  # pragma: allowlist secret

#: ``(platform, arch)`` pairs the install command is declared for. The release has no
#: Windows launcher this plugin can use (``bin/spotbugs`` is a POSIX shell script), so
#: Windows installs nothing and says so.
INSTALL_PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
)

#: The name SpotBugs gives Find Security Bugs in ``tool.extensions`` of its SARIF.
FINDSECBUGS_EXTENSION = "com.h3xstream.findsecbugs"

#: ``ExitCodes`` of SpotBugs, set by ``-exitcode``. See the module docstring.
BUGS_FOUND_FLAG = 1
MISSING_CLASS_FLAG = 2
ERROR_FLAG = 4

#: Every combination of the first two flags is a run that finished.
SUCCESS_EXIT_CODES: Set[int] = {0, 1, 2, 3}

#: SARIF level -> ASH severity. See "Severity" in the module docstring.
LEVEL_SEVERITY: Dict[str, str] = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

#: The rule category that marks a security detector in SpotBugs's SARIF
#: (``rules[].properties.tags``).
SECURITY_TAG = "SECURITY"

ARCHIVE_SUFFIXES = (".jar", ".war", ".ear")
SOURCE_SUFFIXES = (".java", ".kt", ".scala", ".groovy")

#: Bytes read from a class file to find its name: the constant pool comes first.
_CLASS_HEADER_READ = 1 << 20
#: Class files tried in one directory before it is given up on.
_CLASS_PROBES = 3
#: Windows caps a command line at 32,767 characters; the margin leaves room for quoting.
_MAX_COMMAND_LINE_CHARS = 24_000


# ---------------------------------------------------------------------------
# Finding the JVM inputs
# ---------------------------------------------------------------------------


class JvmInputs(NamedTuple):
    """What SpotBugs is handed: archives, and the roots of class directories."""

    archives: List[Path]
    class_roots: List[Path]

    @property
    def empty(self) -> bool:
        return not self.archives and not self.class_roots

    def paths(self) -> List[Path]:
        return [*self.class_roots, *self.archives]


def _parse_this_class(data: bytes) -> Optional[str]:
    """The internal name of the class in ``data`` (``org/example/Foo``), or None.

    Reads the constant pool of a class file (JVMS 4.4) up to ``this_class``.
    """
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return None
    count = struct.unpack_from(">H", data, 8)[0]
    offset = 10
    index = 1
    utf8: Dict[int, Tuple[int, int]] = {}
    classes: Dict[int, int] = {}
    try:
        while index < count:
            tag = data[offset]
            if tag == 1:
                length = struct.unpack_from(">H", data, offset + 1)[0]
                utf8[index] = (offset + 3, length)
                offset += 3 + length
            elif tag == 7:
                classes[index] = struct.unpack_from(">H", data, offset + 1)[0]
                offset += 3
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                offset += 5
            elif tag in (5, 6):
                # Long and double take two constant pool slots.
                offset += 9
                index += 1
            elif tag in (8, 16, 19, 20):
                offset += 3
            elif tag == 15:
                offset += 4
            else:
                return None
            index += 1
        _access, this_class = struct.unpack_from(">HH", data, offset)
    except (IndexError, struct.error):
        return None
    span = utf8.get(classes.get(this_class, -1))
    if span is None:
        return None
    start, length = span
    raw = data[start : start + length]
    if len(raw) != length:
        return None
    return raw.decode("utf-8", errors="replace")


def class_root_of(class_file: Path) -> Optional[Path]:
    """The directory a class file's package path hangs from, or None.

    ``/b/classes/org/x/Foo.class`` holding ``org/x/Foo`` is rooted at ``/b/classes``.
    None when the file cannot be read, is not a class file, or is not at the path its
    own name gives.
    """
    try:
        with open(class_file, "rb") as handle:
            data = handle.read(_CLASS_HEADER_READ)
    except OSError:
        return None
    name = _parse_this_class(data)
    if not name:
        return None
    suffix = "/" + name + ".class"
    posix = Path(class_file).as_posix()
    if not posix.endswith(suffix) or len(posix) == len(suffix):
        return None
    return Path(posix[: -len(suffix)])


def discover_jvm_inputs(target: Path, skip_dirs: Sequence[Path] = ()) -> JvmInputs:
    """The JVM archives and class roots under ``target``.

    No link is followed, and a link is never an input: the target's own files are
    what the scan reads. A directory in ``skip_dirs`` and any ``.git`` directory is
    not entered.
    """
    root = os.path.abspath(target)
    skip = {os.path.abspath(p) for p in skip_dirs}
    archives: List[Path] = []
    roots: List[Path] = []
    probes: Dict[str, int] = {}
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d != ".git"
            and os.path.join(current, d) not in skip
            and not os.path.islink(os.path.join(current, d))
        )
        under_known_root = any(
            current == str(r) or current.startswith(str(r) + os.sep) for r in roots
        )
        for name in sorted(filenames):
            full = os.path.join(current, name)
            if os.path.islink(full):
                continue
            lower = name.lower()
            if lower.endswith(ARCHIVE_SUFFIXES):
                archives.append(Path(full))
            elif (
                lower.endswith(".class")
                and not under_known_root
                and probes.get(current, 0) < _CLASS_PROBES
            ):
                probes[current] = probes.get(current, 0) + 1
                found = class_root_of(Path(full))
                if found is not None and found not in roots:
                    roots.append(found)
                    under_known_root = True
    return JvmInputs(archives=archives, class_roots=roots)


def _source_index(target: Path, skip_dirs: Sequence[Path] = ()) -> Dict[str, List[str]]:
    """Source files under ``target``: ``{file name: [path relative to target, ...]}``."""
    root = os.path.abspath(target)
    skip = {os.path.abspath(p) for p in skip_dirs}
    index: Dict[str, List[str]] = {}
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d != ".git"
            and os.path.join(current, d) not in skip
            and not os.path.islink(os.path.join(current, d))
        )
        for name in filenames:
            if not name.lower().endswith(SOURCE_SUFFIXES):
                continue
            full = os.path.join(current, name)
            if os.path.islink(full):
                continue
            relative = Path(os.path.relpath(full, root)).as_posix()
            index.setdefault(name, []).append(relative)
    return index


def resolve_source_uri(uri: str, index: Dict[str, List[str]]) -> str:
    """``uri`` as the one source file in ``index`` that ends with it, else ``uri``."""
    name = uri.rsplit("/", 1)[-1]
    matches = [p for p in index.get(name, []) if p == uri or p.endswith("/" + uri)]
    return matches[0] if len(matches) == 1 else uri


# ---------------------------------------------------------------------------
# Installing the pinned release
# ---------------------------------------------------------------------------


def install_pinned_spotbugs(bin_dir: str | Path) -> Path:
    """Install the pinned SpotBugs and Find Security Bugs; return the launcher path.

    SpotBugs is a directory (``bin/``, ``lib/``, ``plugin/``), not one executable, so
    it does not fit the single-binary installer of ``utils/tool_downloads.py``. The
    release is extracted to ``<bin_dir>/spotbugs-<version>``, the Find Security Bugs
    jar is put in its ``plugin`` directory (where SpotBugs loads plugins from), and
    ``<bin_dir>/spotbugs`` links to the launcher script, which resolves the link to
    find its installation. Both downloads are checked against the pinned digests
    before anything is extracted or linked.
    """
    bin_path = Path(bin_dir).absolute()
    home = bin_path / f"spotbugs-{SPOTBUGS_VERSION}"
    bin_path.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ash-spotbugs-") as scratch:
        scratch_dir = Path(scratch)
        archive = download_file(
            SPOTBUGS_URL,
            scratch_dir,
            expected_sha256=SPOTBUGS_SHA256,
        )
        plugin_jar = download_file(
            FINDSECBUGS_URL,
            scratch_dir,
            expected_sha256=FINDSECBUGS_SHA256,
        )
        staged = scratch_dir / "extracted"
        staged.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            if hasattr(tarfile, "data_filter"):
                tar.extractall(staged, filter="data")
            else:  # pragma: no cover - Python without the extraction filters
                raise ScannerError(
                    "this Python cannot extract an archive safely (no tarfile "
                    "extraction filters); update Python"
                )
        extracted = staged / f"spotbugs-{SPOTBUGS_VERSION}"
        if not (extracted / "bin" / "spotbugs").is_file():
            raise ScannerError(
                f"the SpotBugs {SPOTBUGS_VERSION} archive has no bin/spotbugs launcher"
            )
        plugin_dir = extracted / "plugin"
        plugin_dir.mkdir(exist_ok=True)
        (plugin_dir / f"findsecbugs-plugin-{FINDSECBUGS_VERSION}.jar").write_bytes(
            Path(plugin_jar).read_bytes()
        )
        launcher = extracted / "bin" / "spotbugs"
        launcher.chmod(0o755)
        if home.exists():
            raise ScannerError(
                f"{home.as_posix()} already exists; remove it to reinstall SpotBugs"
            )
        # The scratch directory can be on another filesystem than the bin directory.
        shutil.move(str(extracted), str(home))
    link = bin_path / "spotbugs"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(home / "bin" / "spotbugs")
    return link


def spotbugs_install_commands() -> "Dict[str, Dict[str, List[CustomCommand]]]":
    """The ``custom_install_commands`` table: one command per supported platform."""
    bin_dir = current_bin_path()
    if bin_dir is None:
        command = refusing_install_command(NO_BIN_DIRECTORY)
    else:
        module = "automated_security_helper.plugin_modules.ash_spotbugs_plugins"
        script = (
            "import sys; "
            f"from {module}.spotbugs_scanner import install_pinned_spotbugs; "
            "install_pinned_spotbugs(sys.argv[1])"
        )
        command = CustomCommand(
            args=[sys.executable, "-c", script, bin_dir.absolute().as_posix()]
        )
    table: "Dict[str, Dict[str, List[CustomCommand]]]" = {}
    for target_platform, arch in INSTALL_PLATFORMS:
        table.setdefault(target_platform, {})[arch] = [command]
    return table


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------


class SpotBugsScannerConfigOptions(ScannerOptionsBase):
    confidence: Annotated[
        Literal["low", "medium", "high"],
        Field(
            description=(
                "The lowest confidence SpotBugs reports: `high` is high only, `medium` "
                "is medium and high (SpotBugs's own default), `low` is everything."
            ),
        ),
    ] = "medium"
    effort: Annotated[
        Literal["min", "less", "default", "more", "max"],
        Field(
            description=(
                "SpotBugs analysis effort (`-effort`). `max` finds more and can need "
                "more memory than the default 768 MB heap."
            ),
        ),
    ] = "default"
    security_only: Annotated[
        bool,
        Field(
            description=(
                "Keep only results from detectors in SpotBugs's SECURITY category "
                "(Find Security Bugs and the core security detectors). Off keeps every "
                "SpotBugs result, style and performance included."
            ),
        ),
    ] = True


class SpotBugsScannerConfig(ScannerPluginConfigBase):
    name: Literal["spotbugs"] = "spotbugs"
    enabled: bool = True
    options: Annotated[
        SpotBugsScannerConfigOptions,
        Field(description="Configure the spotbugs scanner"),
    ] = SpotBugsScannerConfigOptions()


def _level_name(level: Any) -> Optional[str]:
    """A SARIF level as its lower-case name, whether it is an enum or a string."""
    if level is None:
        return None
    return str(getattr(level, "value", level)).lower()


@ash_scanner_plugin
class SpotBugsScanner(ScannerPluginBase[SpotBugsScannerConfig]):
    """JVM bytecode security analysis using SpotBugs and Find Security Bugs."""

    #: Not Python-only: SpotBugs is a Java program, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    # The detectors are inside the installed jars and the analysis reads no network.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = set(SUCCESS_EXIT_CODES)
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    _inputs: Optional[JvmInputs] = PrivateAttr(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = SpotBugsScannerConfig()
        self.command = "spotbugs"
        self.subcommands = []
        self.tool_type = ScannerToolType.SAST
        # The argv is assembled in _build_arguments; ToolArgs stays empty so nothing
        # from the base resolver can add a token SpotBugs would read as an input.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "SpotBugsScanner":
        """Install the pinned release; see ``install_pinned_spotbugs``."""
        self.custom_install_commands.update(spotbugs_install_commands())
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> SpotBugsScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, SpotBugsScannerConfigOptions):
            return options
        return SpotBugsScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _skipped_dirs(self, target: Path) -> List[Path]:
        """ASH's output directories inside ``target``, as paths."""
        found: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            found.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in found:
                found.append(relative)
        return [Path(os.path.abspath(Path(target) / relative)) for relative in found]

    def _build_arguments(self, inputs: JvmInputs, results_file: Path) -> List[str]:
        """The full SpotBugs argv for one target.

        Options first, each as one token; the inputs are absolute paths, which
        cannot be read as an option.
        """
        options = self._options()
        args: List[str] = [
            self.command or "spotbugs",
            "-textui",
            "-exitcode",
            f"-{options.confidence}",
            f"-effort:{options.effort}",
            f"-sarif={results_file.as_posix()}",
        ]
        args.extend(path.absolute().as_posix() for path in inputs.paths())
        if sum(len(a) + 1 for a in args) > _MAX_COMMAND_LINE_CHARS:
            raise ScannerError(
                f"{len(inputs.paths())} JVM inputs do not fit one SpotBugs command "
                "line; narrow the scan target to the build output directories"
            )
        return args

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args,
        **kwargs,
    ) -> Any:
        """Find the JVM inputs; with none, skip cleanly; otherwise the template scan."""
        self._inputs = None
        if not self._target_is_empty(Path(target)):
            found = discover_jvm_inputs(Path(target), self._skipped_dirs(Path(target)))
            if found.empty:
                # The shape of the base class's empty-target skip: the tool is not
                # started, no error is recorded, and the row says why.
                self.exit_code = 0
                self.start_time = None
                self.end_time = None
                self.output = []
                self._reset_errors()
                reason = (
                    f"{self.__class__.__name__} found no compiled JVM code (.class, "
                    ".jar, .war or .ear files) in the target; SpotBugs reads bytecode, "
                    "so there is nothing for it to scan"
                )
                self._nothing_scanned_reason = reason
                self._plugin_log(
                    f"{reason}. Not running the tool on {target_type}.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return True
            self._inputs = found
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one SpotBugs run.

        ``global_ignore_paths`` is not translated into SpotBugs filters: it is applied
        to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("SpotBugsScanner has no results directory")
        # One instance scans the source and then the converted target, and the base
        # class keeps the worst exit code across runs.
        self.exit_code = 0
        inputs = self._inputs or discover_jvm_inputs(
            Path(target), self._skipped_dirs(Path(target))
        )
        if inputs.empty:
            raise ScannerError("no compiled JVM code in the target")
        # Absolute: SpotBugs runs with its working directory at the source directory.
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "spotbugs.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        final_args = self._build_arguments(inputs, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run that did not finish.

        The error flag (4) means SpotBugs hit a serious analysis error; any code
        outside 0 to 3 is not one it documents. Raised before reading so a partial
        report cannot pass as a complete one.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"spotbugs exited {self.exit_code}; with -exitcode it exits 0 to 3 "
                "when it finished (1 bugs found, 2 classes were missing) and 4 or "
                "more on an analysis error, so this run failed"
            )
        return super()._read_results_file(results_file)

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where SpotBugs' log is, without quoting the log."""
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            return f"{detail} (spotbugs was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        return (
            f"{detail} (exit code {self.exit_code}). spotbugs' log is not quoted "
            f"here; see {log_path.as_posix()}"
        )

    # ------------------------------------------------------------------
    # The report
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_tags(sarif_report: SarifReport) -> Dict[str, Set[str]]:
        """``{rule id: categories}`` from the driver's rule descriptors."""
        tags: Dict[str, Set[str]] = {}
        for run in sarif_report.runs or []:
            driver = run.tool.driver if run.tool else None
            for rule in (driver.rules if driver else None) or []:
                properties = rule.properties
                tags[rule.id] = set(getattr(properties, "tags", None) or [])
        return tags

    @staticmethod
    def _require_findsecbugs(sarif_report: SarifReport) -> None:
        """Fail a run whose SARIF does not list Find Security Bugs as loaded."""
        loaded: Set[str] = set()
        for run in sarif_report.runs or []:
            for extension in (run.tool.extensions if run.tool else None) or []:
                loaded.add(extension.name)
        if FINDSECBUGS_EXTENSION not in loaded:
            raise ScannerError(
                "the Find Security Bugs plugin was not loaded by SpotBugs, so the "
                "security detectors did not run. Install it with `ash dependencies "
                "install --config-overrides 'ash_plugin_modules+=[\"automated_security_"
                "helper.plugin_modules.ash_spotbugs_plugins\"]' --tool spotbugs`, or "
                "put findsecbugs-plugin.jar in the plugin directory of the SpotBugs "
                "installation"
            )

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Check the plugin loaded, keep security results, rate them, fix paths."""
        self._require_findsecbugs(sarif_report)
        if self.exit_code is not None and self.exit_code & MISSING_CLASS_FLAG:
            self._plugin_log(
                "SpotBugs reported classes it needed and did not find (library "
                "classes the analysed code calls). Findings that depend on them can "
                "be missed.",
                level=logging.INFO,
            )
        rule_tags = self._rule_tags(sarif_report)
        security_only = self._options().security_only
        index: Optional[Dict[str, List[str]]] = None
        for run in sarif_report.runs or []:
            if security_only and run.results:
                run.results = [
                    result
                    for result in run.results
                    if SECURITY_TAG in rule_tags.get(result.ruleId or "", set())
                ]
            for result in run.results or []:
                name = _level_name(result.level) or "warning"
                severity = LEVEL_SEVERITY.get(name, "HIGH")
                if name not in LEVEL_SEVERITY:
                    result.level = Level.error
                result.kind = Kind.fail
                tags = list(getattr(result.properties, "tags", None) or [])
                for tag in ("security", "jvm"):
                    if tag not in tags:
                        tags.append(tag)
                if result.properties is None:
                    result.properties = PropertyBag(tags=tags)
                else:
                    result.properties.tags = tags
                setattr(result.properties, "issue_severity", severity)  # noqa: B010
                for location in result.locations or []:
                    physical = location.physicalLocation
                    artifact = physical.root.artifactLocation if physical else None
                    if artifact is None or not artifact.uri:
                        continue
                    if index is None:
                        index = _source_index(
                            Path(target), self._skipped_dirs(Path(target))
                        )
                    artifact.uri = resolve_source_uri(artifact.uri, index)
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "spotbugs")
        if not found:
            ASH_LOGGER.warning(
                "spotbugs executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_spotbugs_plugins\"]' --tool spotbugs`. SpotBugs also needs a "
                "Java runtime (JAVA_HOME or java on PATH)."
            )
        return found is not None


__all__ = [
    "ARCHIVE_SUFFIXES",
    "FINDSECBUGS_EXTENSION",
    "JvmInputs",
    "LEVEL_SEVERITY",
    "SUCCESS_EXIT_CODES",
    "SpotBugsScanner",
    "SpotBugsScannerConfig",
    "SpotBugsScannerConfigOptions",
    "class_root_of",
    "discover_jvm_inputs",
    "install_pinned_spotbugs",
    "resolve_source_uri",
    "spotbugs_install_commands",
]
