"""Module containing the Bandit security scanner implementation."""

import configparser
import fnmatch
import glob
import logging
import os
import subprocess
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from pydantic import Field, PrivateAttr
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginConfigBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    SarifReport,
)
from automated_security_helper.utils.link_exclusions import walked_files
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.utils.scanned_tree import REASON_LINK_LEAVES_TREE
from automated_security_helper.utils.scan_output_dirs import (
    PatternSyntax,
    escape_for_pattern,
)
from automated_security_helper.utils.sarif_utils import mask_secrets_in_sarif
from automated_security_helper.utils.suppression_matcher import active_ignore_paths
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command


_GLOB_CHARACTERS = set("*?[]")

#: What a link's ``--exclude`` entry cannot hold: bandit splits the value on
#: commas, a line feed cannot be passed at all (``_execute_scan`` refuses the
#: scan rather than let the base class drop the whole ``--exclude`` argument),
#: and a NUL ends a C string, so exec refuses the whole command line with it
#: (Python raises ``ValueError: embedded null byte`` before anything starts).
#: A carriage return is none of these: the flag-key check admits it (its ``.``
#: matches everything but a line feed), so an entry carrying one reaches exec
#: and bandit as written. Glob characters are escaped (``glob.escape``), not
#: refused.
_BANDIT_EXCLUDE_UNSAFE = frozenset(",\n\0")

#: bandit's own default ``--exclude`` value (``bandit.core.constants.EXCLUDE`` in
#: bandit 1.9.4). Any ``--exclude`` passed on the command line replaces it, and ASH
#: always passes one, so these are passed too; without them ``.tox``, ``.eggs`` and
#: ``*.egg`` trees of installed third-party code were scanned.
BANDIT_DEFAULT_EXCLUDES = (
    ".svn",
    "CVS",
    ".bzr",
    ".hg",
    ".git",
    "__pycache__",
    ".tox",
    ".eggs",
    "*.egg",
)


#: The longest ``--exclude=...`` argument passed where arguments are bounded one by
#: one: Linux refuses one argument longer than 128 KiB (MAX_ARG_STRLEN) with E2BIG,
#: so 120 KiB leaves room for the rest of the command line.
_EXCLUDE_ARGUMENT_LIMIT = 120 * 1024

#: Windows bounds the WHOLE command line CreateProcess is given, not one argument:
#: "The maximum length of this string is 32,767 characters, including the Unicode
#: terminating null character" (CreateProcessW, lpCommandLine), so the text itself
#: has to stay one character shorter, and it is counted in UTF-16 units
#: (``_command_line_units``).
_WINDOWS_COMMAND_LINE_LIMIT = 32767

#: What the Windows bound keeps free of the arguments measured here. The
#: resolved command starts with bare ``bandit``, but the scan runs it through
#: ``uv tool run --from <spec> ...`` (``_try_uv_tool_execution``, the default),
#: whose own path and flags add a hundred characters or more that the measured
#: line does not hold; a line filled to the limit went over it in CreateProcess
#: (WinError 206) once that prefix was added. Two KiB covers the prefix, as the
#: 8 KiB under MAX_ARG_STRLEN does for the rest of the line on Linux.
_WINDOWS_COMMAND_LINE_MARGIN = 2048


def _command_line_units(line: str) -> int:
    """``line``'s length as Windows counts a command line: in UTF-16 units.

    ``len`` counts code points, and a character outside the Basic Multilingual
    Plane (an emoji in a path) is one code point but two UTF-16 units, so a
    line measured by ``len`` could pass the bound and still exceed it.
    """
    return len(line.encode("utf-16-le")) // 2


def _exclude_fits(token: str, rest: Sequence[str], platform: str = os.name) -> bool:
    """Whether the ``--exclude=...`` ``token`` fits the command line beside ``rest``.

    ``rest`` is every other argument of the resolved command. On Windows the
    whole line, as ``subprocess`` builds it (``list2cmdline``), has to stay
    under 32,767 UTF-16 units (that figure counts the terminating NUL) less
    the margin the uv wrapper needs (``_WINDOWS_COMMAND_LINE_MARGIN``), so the
    budget for the token is what the other arguments leave; elsewhere one
    argument is bounded on its own (``_EXCLUDE_ARGUMENT_LIMIT``, in UTF-8 bytes
    as exec passes them, ``_argument_length``). A fixed 24 KiB bound on Windows
    refused scans whose required entries fit the real line.
    """
    if platform == "nt":
        line = subprocess.list2cmdline([*rest, token])
        return _command_line_units(line) < (
            _WINDOWS_COMMAND_LINE_LIMIT - _WINDOWS_COMMAND_LINE_MARGIN
        )
    return _argument_length(token) <= _EXCLUDE_ARGUMENT_LIMIT


def _command_line_bound_text(platform: str = os.name) -> str:
    """The bound ``_exclude_fits`` applies on ``platform``, for an error message."""
    if platform == "nt":
        return (
            f"the {_WINDOWS_COMMAND_LINE_LIMIT}-character command line Windows "
            f"allows, less the {_WINDOWS_COMMAND_LINE_MARGIN} characters kept for "
            "the uv wrapper that runs bandit"
        )
    return f"one command-line argument ({_EXCLUDE_ARGUMENT_LIMIT} bytes)"


def _holds_a_line_break(text: str) -> bool:
    """Whether ``text`` holds a line feed.

    An ``--exclude=`` key holding one fails the base class's flag-key check
    (``_VALID_FLAG_KEY_PATTERN``, whose ``.`` matches every character but a
    line feed), which then drops the WHOLE argument with a warning and runs
    bandit with no exclusion at all: the links that leave the tree included. So
    no entry with one is emitted, and ``_execute_scan`` refuses the scan when the
    target path itself holds one. A carriage return passes that check and
    reaches exec and bandit unchanged, so it is not refused: refusing it said
    bandit "would run with no exclusion at all", which was not so.
    """
    return "\n" in text


def _cannot_be_passed(text: str) -> bool:
    """Whether ``text`` holds a line break or a NUL, which no ``--exclude`` entry can carry.

    A line break fails the base class's flag-key check (``_holds_a_line_break``).
    A NUL cannot be in any argument: exec refuses the whole command line, and
    Python raises ``ValueError`` before bandit starts, so the scan failed on
    the target instead of excluding one path. An ``excluded_paths`` or ignore
    path entry holding one gets no bandit form; a file-system path cannot hold
    one, so the anchors and links never do.
    """
    return _holds_a_line_break(text) or "\0" in text


def _argument_length(text: str) -> int:
    """The byte length of ``text`` as exec passes it.

    A path with a byte that is not UTF-8 reaches Python as a surrogate escape
    (``os.fsdecode``); a strict ``str.encode`` raises ``UnicodeEncodeError`` on
    it, which failed the scan of such a tree. ``surrogateescape`` gives the bytes
    exec will pass.
    """
    return len(text.encode("utf-8", "surrogateescape"))


def _paths_holding_glob_characters(target: Path) -> List[str]:
    """The file paths under ``target`` with ``*?[]`` below it, as bandit spells them.

    bandit walks ``os.walk(<target as given>)`` and joins each file with
    ``os.path.join(root, name)``. Every --exclude entry ASH emits holds ``*`` or
    ``?`` after the target, so only a path with such a character below the
    target can hold an entry as text.
    """
    top = str(target)
    found = []
    for root, _dirs, files in os.walk(top):
        below = root[len(top) :]
        for name in files:
            if _GLOB_CHARACTERS & set(below + name):
                found.append(os.path.join(root, name))
    return found


def _entries_no_path_holds_as_text(
    target: Path,
    ignore_entries: List[str],
    output_entries: List[Tuple[str, Path]],
    holding: Optional[List[str]] = None,
    values: Iterable[str] = (),
    level: int = logging.WARNING,
    applied_after_scan: bool = False,
) -> List[str]:
    """The entries, less any that a file path under ``target`` holds as text.

    ``values`` are the configured values to redact from the log line
    (``text_without_values``): an ``excluded_paths`` entry can be read from the
    environment, and the line names the dropped globs built from it. A value's
    bracketed form (``_not_a_plain_substring``, ``vendo[r]`` for ``vendor``) is
    redacted with it, since that is how the top-level glob spells the value.
    ``level`` is the line's level and ``applied_after_scan`` what the line says
    of the dropped entries' findings: a required entry (an ``excluded_paths``
    entry, a default exclude, an output directory) is applied by nothing after
    the scan, so its drop is a WARNING and the findings are reported; a
    best-effort glob for a global ignore path is covered by the SARIF step, so
    its drop is VERBOSE and the findings are dropped after the scan.

    bandit skips a file whose path contains an --exclude entry as a plain
    substring, as well as one the entry matches as a glob (bandit 1.9.4,
    ``manager._is_file_included``). Measured: ignore path ``docs/*.md`` gave
    ``<src>/docs/*.md``, and bandit skipped ``<src>/docs/*.md/evil.py``, in a
    directory literally named ``*.md``, which the ignore path does not cover.
    Such an entry is left out, with a warning: for a global ignore path the
    SARIF step still drops the findings it covers, but an ``excluded_paths``
    entry or one of bandit's default excludes is applied by nothing after the
    scan, so bandit reads the files it names and reports their findings.
    ``output_entries`` pairs each of ASH's output directories inside ``target``
    (relative to it) with its entry; an entry is kept for paths inside its own
    directory, which it is meant to skip.

    bandit also rewrites an entry that names an existing directory to
    ``<entry>/*`` (``manager.discover_files``), which covers the files of every
    directory the glob matches. Measured: with an empty directory, or a
    directory symlink, literally named ``docs/*.md`` (or ``*.md`` linked to
    ``.``, or ``lib/?``), bandit skipped an ``evil.py`` the ignore path does not
    cover. An entry that names an existing directory is left out too, unless it
    already ends in ``/*``, for which the rewrite only narrows it.

    ``holding`` is ``_paths_holding_glob_characters(target)``, when the caller
    has walked it already, so a caller that filters two entry sets walks once.

    Both checks read the tree once, when the arguments are resolved. A
    directory created under ``target`` between this read and bandit's own walk
    is a change of the scanned tree during the scan, which no check made before
    the scan can follow; ASH reports on the tree as it stood when the scan was
    started.
    """
    if holding is None:
        holding = _paths_holding_glob_characters(target)
    kept = [e for e in ignore_entries if not any(e in path for path in holding)]
    dropped = [e for e in ignore_entries if e not in kept]
    for output_entry, output_dir in output_entries:
        inside = os.path.join(str(target), *output_dir.parts) + os.sep
        outside = [path for path in holding if not path.startswith(inside)]
        if any(output_entry in path for path in outside):
            dropped.append(output_entry)
        else:
            kept.append(output_entry)
    named_directories = [e for e in kept if not e.endswith("/*") and os.path.isdir(e)]
    kept = [e for e in kept if e not in named_directories]
    dropped += named_directories
    if dropped:
        # Redacted: the globs are built from configured entries, which can come
        # from the environment, and ash.log keeps the line.
        redacted = list(values)
        for value in list(redacted):
            bracketed = _not_a_plain_substring(value)
            if bracketed and bracketed != value:
                redacted.append(bracketed)
        if applied_after_scan:
            consequence = (
                "bandit reads the files these entries name; the SARIF step drops "
                "the findings the global ignore paths cover after the scan."
            )
        else:
            consequence = (
                "bandit reads the files these entries name, and nothing applies "
                "them after the scan, so their findings are reported."
            )
        ASH_LOGGER.log(
            level,
            text_without_values(
                f"Not passing {dropped} to bandit --exclude: a file path under "
                f"'{target}' contains it as text, or it names an existing "
                f"directory, and bandit would skip files it does not cover. "
                f"{consequence}",
                redacted,
            ),
            extra=NO_MARKUP,
        )
    return kept


def _spelled_path(text: str, *, uri: bool, windows: Optional[bool] = None) -> str:
    """A bandit metrics key (``uri=False``) or notification URI (``uri=True``) as one comparable path.

    bandit's SARIF names a skipped file as ``to_uri(fname)``: a ``file://`` URI
    for an absolute path, a percent-encoded POSIX path otherwise; its metrics
    key is the same ``fname`` as walked, not encoded. Only the URI is unquoted,
    with ``surrogateescape`` so a non-UTF-8 name (which ``to_uri`` writes as
    ``%FF``) decodes to the surrogate-escaped text the walked key holds.
    Unquoting the key too read a file named ``x%41.py`` as ``xA.py``, so a
    skipped file with a ``%`` in its name was counted as scanned and two
    different files could collide.

    On Windows ``to_uri`` spells an absolute path as ``file:///C:/x.py`` and a
    UNC path as ``file://server/share/x.py`` (``PureWindowsPath.as_uri``), while
    the key is the path as walked, ``C:\\x.py`` and ``\\\\server\\share\\x.py``.
    Dropping the prefix alone left ``/C:/x.py`` against ``C:/x.py`` and
    ``server/share/x.py`` against ``//server/share/x.py``, so no skipped file
    matched its key there and every one was counted as scanned.

    Those two readings apply where bandit writes them, on Windows
    (``windows``, the running platform by default). On POSIX a root directory
    named like a drive, ``/a:/x.py``, is spelled ``file:///a:/x.py``, and
    reading its ``/a:/`` as a drive dropped the slash the key keeps.
    """
    from urllib.parse import unquote

    if windows is None:
        windows = os.name == "nt"
    spelled = text
    if uri:
        spelled = unquote(spelled, errors="surrogateescape")
        if spelled.startswith("file://"):
            spelled = spelled[len("file://") :]
            if (
                windows
                and len(spelled) >= 3
                and spelled[0] == "/"
                and spelled[1].isascii()
                and spelled[1].isalpha()
                and spelled[2] == ":"
            ):
                # ``file:///C:/x.py``: the key starts at the drive letter.
                spelled = spelled[1:]
            elif windows and not spelled.startswith("/"):
                # ``file://server/share/x.py``: the key is ``\\server\share\x.py``.
                spelled = "//" + spelled
    spelled = spelled.replace("\\", "/")
    while spelled.startswith("./"):
        spelled = spelled[2:]
    return spelled


def _skipped_file_paths(run: Any) -> set:
    """The files a bandit run's SARIF says it skipped, as ``_spelled_path`` spells them.

    bandit 1.9.4 writes one ``toolConfigurationNotifications`` entry per file it
    could not parse (``manager.skipped``), each with the file's location.
    """
    skipped = set()
    for invocation in getattr(run, "invocations", None) or []:
        notes = getattr(invocation, "toolConfigurationNotifications", None) or []
        for note in notes:
            for location in getattr(note, "locations", None) or []:
                physical = getattr(location, "physicalLocation", None)
                physical = getattr(physical, "root", physical)
                artifact = getattr(physical, "artifactLocation", None)
                uri = getattr(artifact, "uri", None)
                if isinstance(uri, str) and uri:
                    skipped.add(_spelled_path(uri, uri=True))
    return skipped


#: bandit's file selection when no ``--configfile`` is passed
#: (``bandit/core/config.py``, 1.9.4).
_BANDIT_DEFAULT_INCLUDE = ("*.py", "*.pyw")


def _config_file_filters(final_args: Sequence[Any]) -> Tuple[List[str], List[str]]:
    """bandit's ``include`` globs and ``exclude_dirs`` from the ``--configfile`` in ``final_args``.

    As bandit 1.9.4 reads them (``core/config.py``: the top level of a YAML
    file, or ``[tool.bandit]`` of a ``.toml`` file; ``core/manager.py``
    ``discover_files``: ``include`` selects the files, and ``exclude_dirs``
    entries join the ``--exclude`` entries as one list, each matched the same
    way). The scanned-file check has to apply the same selection: an operator
    config that leaves every Python file out was read as bandit having scanned
    no file, an error. With no ``--configfile`` bandit includes ``*.py`` and
    ``*.pyw``; with one, a non-empty ``include`` list is used as written and
    anything else (no key, an empty list) means ``*.py`` only, which is
    bandit's ``or ["*.py"]`` fallback. A file that cannot be read or parsed, or
    a parse that is not a mapping, leaves the no-config defaults; bandit itself
    then fails the scan on the same file, with its own message.
    """
    include = list(_BANDIT_DEFAULT_INCLUDE)
    exclude_dirs: List[str] = []
    arguments = [str(argument) for argument in final_args]
    config_file: Optional[str] = None
    for index, argument in enumerate(arguments):
        if argument == "--configfile" and index + 1 < len(arguments):
            config_file = arguments[index + 1]
        elif argument.startswith("--configfile="):
            config_file = argument[len("--configfile=") :]
    if config_file is None:
        return include, exclude_dirs
    try:
        with open(config_file, "rb") as handle:
            raw = handle.read()
    except OSError:
        return include, exclude_dirs
    data: Any = None
    if config_file.endswith(".toml"):
        try:
            import tomllib
        except ImportError:  # pragma: no cover - Python 3.10 without tomli
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return include, exclude_dirs
        try:
            data = tomllib.loads(raw.decode("utf-8")).get("tool", {}).get("bandit")
        except (UnicodeDecodeError, ValueError, AttributeError):
            data = None
    else:
        import yaml

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            data = None
    if not isinstance(data, dict):
        return include, exclude_dirs
    configured_include = data.get("include")
    if isinstance(configured_include, list) and configured_include:
        include = [str(item) for item in configured_include]
    else:
        # A config file that sets no include, or an empty one, leaves bandit
        # with ``*.py`` only: ``discover_files`` reads
        # ``get_option("include") or ["*.py"]``, and the ``*.pyw`` default is
        # set only when no config file is given at all (core/config.py).
        include = ["*.py"]
    configured_exclude = data.get("exclude_dirs")
    if isinstance(configured_exclude, list):
        exclude_dirs = [str(item) for item in configured_exclude if str(item)]
    return include, exclude_dirs


def _not_a_plain_substring(literal: str) -> Optional[str]:
    """``literal`` as an ``fnmatch`` glob that matches only itself and holds a
    ``[``, so bandit's substring test cannot fire on an ordinary path.

    bandit skips a file whose path contains an --exclude entry as plain text,
    so a literal ``<anchor>/app.py`` would also skip ``<anchor>/app.py.d/x.py``
    and ``<anchor>/app.pyx.py``. ``<anchor>/app.p[y]`` matches ``<anchor>/app.py``
    as a glob and nothing else, and as text it occurs only in a path that has a
    ``[`` itself, which ``_entries_no_path_holds_as_text`` checks the tree for.

    The bracketed character is the last one that is not ``/``, ``!``, ``^``,
    ``-`` or ``]``, which read as a separator, a negation, a range or the class's
    end inside brackets. A literal made only of those (``-``, ``]]``) has no
    such form and None is returned: passed as it was, ``<anchor>/-`` would be a
    plain substring of ``<anchor>/-x.py`` and make bandit skip that file too.
    """
    for index in range(len(literal) - 1, -1, -1):
        if literal[index] not in "/!^-]":
            return f"{literal[:index]}[{literal[index]}]{literal[index + 1 :]}"
    return None


def bandit_exclude_globs(anchor: str, pattern: str) -> List[str]:
    """bandit ``--exclude`` globs for an ignore path, anchored at ``anchor``.

    Only globs that make bandit skip no file the ignore path does not cover, so
    a glob emitted here may skip fewer files than the ignore path covers, never
    others.
    bandit tests each entry two ways against ``<anchor>/<relative path>``: as an
    ``fnmatch`` glob, where ``*`` crosses ``/``, and as a plain substring. So a
    literal is emitted in a form that is not a plain substring of anything
    (``_not_a_plain_substring``), and a ``**`` shape that has no exact
    ``fnmatch`` form is not emitted. What is not emitted is still scanned, and
    its findings are dropped by the SARIF step, which applies every ignore path;
    a file bandit skipped that the SARIF step would have kept would lose its
    findings instead.

    ASH matches case-sensitively on every platform. bandit's ``fnmatch`` does on
    POSIX, and on Windows it folds both sides to lower case (``os.path.normcase``).
    For a literal, ``*`` and ``?`` that only makes bandit skip, on Windows, another
    spelling of a name the file system already reads as the same file; for a
    character class it can make bandit skip other files (``[A-Z]`` folded is
    ``[a-z]``, which takes ``b.py``), so a pattern with ``[`` or ``]`` is not
    emitted.

    Emitted:

    * a literal (``app.py``, ``src/app.py``), which ASH reads as that path
      only: ``<anchor>/app.p[y]``.
    * ``dir/**`` and ``dir/`` (``dir`` literal, any depth of components):
      ``<anchor>/dir/*``.
    * ``**/dir/**`` and ``**/dir/``: ``<anchor>/dir/*`` and ``<anchor>/*/dir/*``.
    * a pattern without ``**`` that has ``*`` or ``?`` (``src/*.py``):
      ``<anchor>/src/*.py``. ASH matches such a pattern with ``fnmatch`` too.

    Not emitted: a pattern with a ``.`` or empty component, a leading ``./``
    included. ASH's matcher compares a path as it is given and drops no ``./``, so
    ``./app.py`` covers no file of the tree and bandit is told to skip none. Nor a
    pattern or anchor holding a line break or a NUL (``_cannot_be_passed``): the
    argument could not carry it, and the SARIF step applies the ignore path. Nor
    a literal made only of ``/!^-]`` (``_not_a_plain_substring`` has no form for
    it that is not a plain substring of other paths).
    """
    pattern = pattern.replace("\\", "/")
    if pattern.endswith("/") and pattern.strip("/"):
        pattern = pattern.rstrip("/") + "/**"
    anchor_glob = glob.escape(anchor)
    if (
        not pattern.strip("/")
        or "," in pattern
        or "," in anchor
        or _cannot_be_passed(pattern)
        or _cannot_be_passed(anchor)
    ):
        return []
    if "[" in pattern or "]" in pattern:
        # ASH compares a character class as written; bandit's fnmatch folds the
        # pattern and the path to lower case on Windows, which turns [A-Z] into
        # [a-z] and makes bandit skip b.py, a file the ignore path does not cover.
        # No character class reaches bandit. (While ASH lower-cased both sides,
        # bandit 1.9.4 skipped src/b.py for src/[!A-Z].py on every platform.)
        return []
    if "**" not in pattern:
        # A leading "/" names nothing to ASH's matcher, which compares the
        # pattern with the path as written; nor do "." or empty components.
        if pattern.startswith("/") or any(
            part in ("", ".", "..") for part in pattern.split("/")
        ):
            return []
        if _GLOB_CHARACTERS & set(pattern):
            return [f"{anchor_glob}/{pattern}"]
        literal = _not_a_plain_substring(pattern)
        if literal is None:
            return []
        return [f"{anchor_glob}/{literal}"]
    parts = pattern.split("/")
    leading = parts[0] == "**"
    middle = parts[1:-1] if leading else parts[:-1]
    if (
        parts[-1] != "**"
        or not middle
        or any(
            part in ("", ".", "..", "**") or _GLOB_CHARACTERS & set(part)
            for part in middle
        )
    ):
        return []
    directory = "/".join(middle)
    if leading:
        return [f"{anchor_glob}/{directory}/*", f"{anchor_glob}/*/{directory}/*"]
    return [f"{anchor_glob}/{directory}/*"]


def bandit_excluded_path_globs(anchor: str, path: str) -> List[str]:
    """bandit ``--exclude`` globs for an ``excluded_paths`` entry or a known
    directory (``.venv/``), anchored at ``anchor``.

    Such an entry names a path anywhere below the scanned target, bandit's own
    reading, which ASH applies with nothing after the scan. It was emitted as
    ``**/<path>/**``, which bandit only matches inside a directory called
    ``<path>``: a file entry such as ``app.py`` never skipped its file, and
    ``tests/*`` skipped only files in subdirectories. Unanchored, it also
    matched the target's own path, so a project inside a directory named
    ``venv`` had every file skipped, and ``src/vendor`` under a target named
    ``src`` skipped the top-level ``vendor`` too.

    * A file or directory (``app.py``, ``vendor``) or a glob (``*.pyc``,
      ``tests/*``): the files it matches and the files under the directories
      it matches, at the top of the target or below any directory.
    * ``dir/``, ``dir/**``, ``**/dir/**``: only the files under such
      directories. A leading ``**/`` and a leading ``./`` add nothing.
    * ``**`` elsewhere reads as ``*``, which in bandit's ``fnmatch`` crosses
      ``/``, as the old form did.
    * A ``,`` (bandit splits on it), a line break or a NUL (the argument cannot
      carry one; see ``_cannot_be_passed``), a ``.`` or empty component, or
      nothing at all: no entry. The caller warns that such an entry excludes
      nothing.
    * A leading ``/`` is dropped and the rest read relative to the target:
      ``/vendor`` is read as ``vendor`` and does exclude ``<target>/vendor``,
      while an absolute path that repeats the target's own prefix
      (``/home/me/project/vendor`` under ``/home/me/project``) is read as
      ``home/me/project/vendor`` below the target and names nothing there; the
      caller warns about such an entry.

    The same globs tell ASH, after the scan, which findings a client-delivered
    ``excluded_paths`` entry would have kept from bandit
    (``config/client_scanner_exclusions.py``): matched against the finding's
    absolute path as bandit matches them, one builder for both sides.
    """
    spelled = path.replace("\\", "/")
    while spelled.startswith("./"):
        spelled = spelled[2:]
    spelled = spelled.lstrip("/")
    directory_only = False
    if spelled.endswith("/"):
        directory_only = True
        spelled = spelled.rstrip("/")
    if spelled.endswith("/**"):
        directory_only = True
        spelled = spelled[: -len("/**")]
    while spelled.startswith("**/"):
        spelled = spelled[len("**/") :]
    parts = spelled.split("/")
    if (
        not spelled
        or "," in spelled
        or "," in anchor
        or _cannot_be_passed(spelled)
        or _cannot_be_passed(anchor)
        or any(part in ("", ".", "..") for part in parts)
    ):
        return []
    body = "/".join("*" if part == "**" else part for part in parts)
    anchor_glob = glob.escape(anchor)
    entries = [f"{anchor_glob}/{body}/*", f"{anchor_glob}/*/{body}/*"]
    if not directory_only:
        # The top-level file form has to match that one path and be a plain
        # substring of no other; a name with no bracketable character has no
        # such form, and the entries below it (which hold a "*") stand.
        top = body if _GLOB_CHARACTERS & set(body) else _not_a_plain_substring(body)
        if top is not None:
            entries.append(f"{anchor_glob}/{top}")
        entries.append(f"{anchor_glob}/*/{body}")
    return entries


def _spelled_absolute(path: str) -> bool:
    """Whether an ``excluded_paths`` entry is written as an absolute path.

    A leading ``/`` (or ``\\``), or a drive letter (``C:``), on either platform's
    spelling. ``bandit_excluded_path_globs`` drops the leading separator and
    reads the rest relative to the scanned target, so ``/vendor`` still names
    ``<target>/vendor``, while a path that repeats the target's own absolute
    prefix names nothing there; the caller tells the operator what the entry is
    read as.
    """
    spelled = path.replace("\\", "/")
    return spelled.startswith("/") or (
        len(spelled) >= 2 and spelled[0].isalpha() and spelled[1] == ":"
    )


class BanditScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description="Path to Bandit configuration file. A relative path is taken from the directory of the config file that sets it, or from the working directory for --config-overrides, not from the source directory."
            f" {SET_BY_THE_OPERATOR}"
            " ASH does not look for one by name. A file named exactly `.bandit` is passed with `bandit --ini`, and any other file with `bandit --configfile`. Unless config_file names a `.bandit` file that exists, ASH passes bandit an empty config file with `bandit --ini`, so bandit does not read a `.bandit` file from the scanned tree. A path that is not a file is logged as a warning and ignored.",
        ),
    ] = None
    confidence_level: Annotated[
        str,
        Field(
            description="Confidence level for bandit scan (all, low, medium, high)",
            pattern="^(all|low|medium|high)$",
        ),
    ] = "all"
    ignore_nosec: Annotated[
        bool,
        Field(
            description="Whether to ignore #nosec comments in the code",
        ),
    ] = False
    excluded_paths: Annotated[
        List[IgnorePathWithReason],
        Field(
            description="List of paths to exclude from the bandit scan",
        ),
    ] = []
    additional_formats: Annotated[
        List[str],
        Field(
            description="Additional output formats (e.g., html, csv, xml). bandit writes one format per run through a single --format option, and ASH needs that run's output to be SARIF, so these formats are not produced: a value here is accepted and logged as a warning. Convert the SARIF results with ASH's reporters instead.",
        ),
    ] = []
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.bandit.options.tool_version"),
        Field(
            description="Version constraint for bandit tool installation (e.g., '>=1.7.8'). If not specified, uses '>=1.7.8,<2.0.0' for stability."
        ),
    ] = ">=1.7.8,<2.0.0"
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation (default: 300)"),
    ] = 300


class BanditScannerConfig(ScannerPluginConfigBase):
    """Bandit scanner configuration."""

    name: Literal["bandit"] = "bandit"
    enabled: bool = True
    options: Annotated[
        BanditScannerConfigOptions,
        Field(description="Configure Bandit scanner"),
    ] = BanditScannerConfigOptions()


@ash_scanner_plugin
class BanditScanner(ScannerPluginBase[BanditScannerConfig]):
    """Implementation of a Python security scanner using Bandit.

    This scanner uses Bandit to perform static security analysis of Python code
    and returns results in a structured format using the StaticAnalysisReport model.
    """

    #: bandit is a Python package ASH runs through uv. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("BANDIT_",)
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    # The operator's .bandit file, when config_file names one; see
    # _process_config_options.
    _ini_file: Optional[Path] = PrivateAttr(default=None)
    #: The ``.bandit`` exclude warnings already given, by (entry, subject):
    #: ``_ini_excludes`` runs once per scanned target, and each warning is about
    #: the operator's file, not the target, so it is given once per build.
    _ini_warnings_given: Set[Tuple[str, str]] = PrivateAttr(default_factory=set)

    # The uv --from spec the install command and the version probe were built
    # for; _apply_config rebuilds both only when a new configuration changes it.
    _applied_from_spec: Optional[str] = PrivateAttr(default=None)

    def model_post_init(self, context):
        if self.config is None:
            self.config = BanditScannerConfig()
        self.command = "bandit"
        self.tool_type = ScannerToolType.SAST
        self.use_uv_tool = True  # Enable UV tool execution

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # The version probe is recorded here and run once, by the dependency
        # check, the SARIF step or the inventory (resolve_deferred_tool_version):
        # construction must start nothing, whoever constructs the scanner.
        self._applied_from_spec = self._uv_from_spec()
        self._deferred_tool_version_probe = ("bandit", self._applied_from_spec)
        self.description = "Bandit is a Python source code security analyzer."
        self.args = ToolArgs(
            format_arg="--format",
            format_arg_value="sarif",
            output_arg="--output",
            scan_path_arg=None,
            extra_args=self._base_extra_args(),
        )
        super().model_post_init(context)

    @staticmethod
    def _base_extra_args() -> List[ToolExtraArg]:
        """The arguments every bandit run gets before its options are read.

        ``_process_config_options`` appends the configured options after these;
        ``configure`` starts from them again, so a new configuration's options
        replace the old ones instead of doubling or staying stale.
        """
        extra_args = [
            ToolExtraArg(
                key="--recursive",
                value=None,
            ),
        ]
        if ASH_LOGGER.level == logging.DEBUG:
            extra_args.append(
                ToolExtraArg(
                    key="--verbose",
                    value=None,
                )
            )
        return extra_args

    def _get_tool_version_constraint(self) -> str | None:
        """Get version constraint for bandit installation.

        Returns:
            The configured ``tool_version`` constraint, whose default carries an
            upper bound excluding the next major version. No literal is repeated
            here: a copy of the constraint in this docstring went stale against
            the default beside it, which is what made the published docs drop the
            ceiling and tell readers to install an excluded major version.
        """
        # A configured null means "not specified", which the option's own
        # description says uses the default: with None returned instead, the
        # requirement handed to uv had no version constraint at all (any
        # bandit, the next major version included), unlike semgrep's, which
        # falls back to its default range the same way.
        configured = self.config.options.tool_version
        if configured:
            return configured
        return BanditScannerConfigOptions.model_fields["tool_version"].default

    def _get_tool_package_extras(self) -> List[str] | None:
        """Get package extras for bandit installation.

        Returns:
            List of package extras needed for bandit (sarif and toml support)
        """
        # Bandit needs sarif extra for SARIF output format and toml extra for TOML config support
        return ["sarif", "toml"]

    def configure(self, config: ScannerPluginBase | None = None):
        """Configure the scanner with the provided configuration.

        Args:
            config: Scanner configuration

        Raises:
            ScannerError: If configuration fails
        """
        try:
            if config is not None:
                self.config = config
                self._apply_config()

        except Exception as e:
            raise ScannerError(
                f"Failed to configure {self.__class__.__name__}: {str(e)}"
            )

    def _apply_config(self) -> None:
        """Rebuild what construction built from ``self.config``, after it changed.

        The option arguments (``--confidence-level``, ``--configfile`` or
        ``--ini``, ``--ignore-nosec``, the construction-time ``--exclude``) are
        built from the configuration when it is read; swapping the configuration
        alone left the old ones in argv, so a new ``confidence_level`` or
        ``config_file`` was never applied. The arguments start again from the
        base ones and the new options are read once. The ``uv tool install``
        command and the deferred version probe are built from ``tool_version``
        the same way; they are rebuilt only when the new configuration changes
        the ``--from`` spec, so a configuration that differs elsewhere does not
        run the version probe a second time.
        """
        self._process_config_options()
        spec = self._uv_from_spec()
        if spec != self._applied_from_spec:
            self._setup_uv_tool_install_commands()
            self._deferred_tool_version_probe = ("bandit", spec)
            self._applied_from_spec = spec

    def _pre_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        config: Any = None,
        *args,
        **kwargs,
    ) -> bool:
        """The base pre-scan, with a configuration handed to ``scan()`` applied first.

        The executor passes each target's scanner configuration to ``scan()``,
        and the base ``_pre_scan`` replaces ``self.config`` with it after the
        dependency check and without rebuilding anything (``configure()`` is
        called by nothing on that route), so the argv built at construction
        stayed: the old ``--confidence-level``, no ``--ignore-nosec``, the old
        ``--ini`` or ``--configfile``, while the ``--exclude`` rebuilt per scan
        took the new ``excluded_paths`` and the run looked configured. Here a
        configuration that differs from the current one is applied
        (``_apply_config``) before the base runs its dependency check, so the
        check and the argv read the configuration the scan runs under; one
        equal to the current configuration, which the executor passes on every
        target, changes nothing.
        """
        if config is not None:
            if hasattr(config, "model_dump") and callable(config.model_dump):
                config = config.model_dump(by_alias=True)
            replacement = self.config.__class__.model_validate(config)
            if replacement.model_dump(by_alias=True) != self.config.model_dump(
                by_alias=True
            ):
                self.config = replacement
                self._apply_config()
        return super()._pre_scan(target, target_type, None, *args, **kwargs)

    def validate_plugin_dependencies(self) -> bool:
        """Enhanced validation with explicit tool installation.

        Workflow:

        1. If UV tool execution is required but UV is not on PATH, defer to
           :func:`get_uv_tool_command` to see whether a direct binary fallback
           still satisfies the dependency.
        2. If UV is available and the tool is already reachable, succeed.
        3. Otherwise attempt explicit ``uv tool install`` with retry/timeout.
        4. As a last resort, ask :func:`get_uv_tool_command` to resolve the
           command — this consolidates the "uv missing → direct binary → None"
           fallback that used to be open-coded across scanners.

        Returns:
            True if validation passes, False otherwise
        """
        # First, while use_uv_tool still says what construction set: the
        # tool-version probe, which construction leaves to this point.
        self.resolve_deferred_tool_version()
        if not self._validate_uv_tool_availability():
            # UV is required but not present. The consolidated resolver answers
            # a bandit on PATH, if there is one; it runs directly once verified
            # (_take_resolved_command). Any non-None answer used to turn uv off
            # and mark the dependency satisfied with no check of the sarif and
            # toml extras or of tool_version. The resolver is handed this
            # scanner's own offline reading (_is_offline_mode): without it, it
            # followed ASH's global mode alone, so its probe went online for a
            # scanner held offline on its own, and its memo keyed that answer
            # under the mode the probe ran in, not the one this scanner is in.
            command = get_uv_tool_command(
                self.command,
                from_spec=self._uv_probe_from_spec(),
                offline=self._is_offline_mode(),
            )
            if command is not None:
                return self._take_resolved_command(command)
            self._plugin_log(
                "UV tool validation failed - UV is not available but required",
                level=logging.ERROR,
            )
            return False

        # For UV tool-based scanners, attempt explicit installation if needed
        if self.use_uv_tool:
            # Check if tool is already available (UV-installed or pre-installed)
            installation_info = self._get_tool_installation_info()

            if installation_info.get("available"):
                # Runs a verified binary on PATH directly instead of re-resolving
                # through uv, and fails offline with the missing extras named (#520).
                return self._select_tool_execution(installation_info)

            # Tool not available, attempt installation
            self._plugin_log(
                "Bandit not found via UV tool, attempting explicit installation...",
                level=logging.INFO,
            )

            # Attempt explicit tool installation with configured timeout
            timeout = self.config.options.install_timeout if self.config else 300
            retry_config = {
                "max_retries": 3,
                "base_delay": 1.0,
                "max_delay": 60.0,
            }

            if self._install_uv_tool(timeout=timeout, retry_config=retry_config):
                self._plugin_log(
                    "Successfully installed bandit via UV tool", level=logging.INFO
                )
                self.dependencies_satisfied = True
                return True

            self._plugin_log(
                "UV tool installation failed for bandit, falling back to consolidated resolver",
                level=logging.WARNING,
            )

        # Final fallback: the consolidated UV-or-direct-binary resolver. Its
        # answer was tested for None and the route left as it was, so a binary on
        # PATH marked the dependency satisfied while use_uv_tool stayed True and
        # the scan went back through the uv route that had just failed. The
        # scanner's own offline reading reaches the resolver here as above.
        command = get_uv_tool_command(
            self.command,
            from_spec=self._uv_probe_from_spec(),
            offline=self._is_offline_mode(),
        )
        if command is None:
            return False
        return self._take_resolved_command(command)

    def _take_resolved_command(self, command: List[str]) -> bool:
        """Set the route from ``get_uv_tool_command``'s answer, and decide the dependency.

        A ``uv`` answer (bare, or by its path) keeps the uv route. A direct binary
        on PATH is verified as ``_select_tool_execution`` verifies one
        (``utils/pre_installed_tool.py``: the sarif and toml extras,
        ``tool_version``): one that falls short is refused with what is missing
        named, since running it would fail at ``--format sarif`` or report with
        the wrong version; one that cannot be verified runs, with a warning,
        because on neither route that reaches here did uv resolve the requirement
        (uv is absent, or its install of the tool failed). A verified binary runs
        directly: ``use_uv_tool`` is turned off, which the final fallback never
        did before.
        """
        if Path(command[0]).name.lower().removesuffix(".exe") == "uv":
            # The resolver names uv bare or by its path, on Windows as uv.exe;
            # each is the uv route, which stays on. (Compared as the bare word,
            # an absolute uv path read as a bandit binary and was "verified" as
            # one; compared by name alone, uv.exe still did.)
            self.dependencies_satisfied = True
            return True
        from automated_security_helper.utils.pre_installed_tool import (
            build_requirement,
            verify_pre_installed_tool,
        )
        from automated_security_helper.utils.uv_tool_runner import (
            find_uv_or_none,
            shown_uv_output,
        )

        executable = command[0]
        extras = self._get_tool_package_extras()
        constraint = self._get_tool_version_constraint()
        # The package that provides the command, when named apart from it, as
        # _select_tool_execution builds its requirement: the copy is verified
        # against the requirement the scan runs under, not one named after the
        # executable.
        package = self.uv_tool_package_name or self.command
        requirement = build_requirement(package, extras, constraint)
        # The constraint and the check's detail can hold a configured value, and a
        # configured value can come from the environment: redacted as the mixin
        # redacts the same lines (shown_uv_output), since the verify detail can
        # respell an environment-read tool_version in uv's own words, which the
        # plain value match does not see. The reason reaches the reports through
        # dependency_unavailable_reason.
        values = self._values_to_redact()
        checked = verify_pre_installed_tool(
            executable,
            package,
            extras,
            constraint,
            uv_executable=find_uv_or_none(),
            values=values,
        )

        def _shown(text: str) -> str:
            return shown_uv_output(
                text,
                values,
                plugin_inputs=self._uv_run_inputs_for_records(),
                tool_name=self.command,
                limit=None,
            )

        if checked.status == "unsatisfied":
            reason = _shown(
                f"{self.command} at {executable} cannot be used: {checked.detail}. "
                f"Install one that satisfies {requirement!r}, e.g. "
                f"`uv tool install '{requirement}'`."
            )
            self.dependency_unavailable_reason = reason
            self._plugin_log(reason, level=logging.ERROR)
            self.dependencies_satisfied = False
            return False
        if checked.status == "satisfied":
            self._plugin_log(
                _shown(
                    f"Using pre-installed {self.command} at {executable} directly; "
                    f"it satisfies {requirement!r}"
                ),
                level=logging.INFO,
            )
        else:
            self._plugin_log(
                _shown(
                    f"Using pre-installed {self.command} at {executable} directly "
                    f"though it could not be verified against {requirement!r}: "
                    f"{checked.detail}. No uv-managed {self.command} resolved "
                    "instead (uv absent, or its install of the tool failed)."
                ),
                level=logging.WARNING,
            )
        version = getattr(checked, "version", None)
        if version:
            # The copy that runs is this one, so the version the reports name
            # (the SARIF scanner_version) is its own: the deferred probe read
            # the version of uv's environment, which is not what runs now.
            self.tool_version = version
        self.use_uv_tool = False
        self.dependencies_satisfied = True
        return True

    def _process_config_options(self):
        # The operator's config file, if there is one. A config file inside the
        # scanned tree does not choose it (config/tool_config_trust.py), and ASH
        # does not look for .bandit, bandit.yaml or bandit.toml by name: their
        # skips and exclude_dirs would let the repository decide what its scan
        # reports. A scan always passes an --ini (the operator's .bandit, or an
        # empty one ASH writes), which ends bandit's own .bandit search.
        #
        # The configured value is read as the tool will read it (resolved from
        # the scanned tree, not from whatever directory the process runs in),
        # and one that is a work product the scan derived from the repository
        # being scanned (under the output or work directory) is not handed to
        # bandit unless the operator's own configuration names it; see
        # config/path_trust.py. A configured value that is refused or missing
        # takes no discovered replacement: bandit gets the empty ini.
        #
        # The option arguments start again from the base ones on every call, so
        # a second call (configure() after the configuration changed, or a
        # caller that processes the options again) builds each flag once. Before,
        # every call appended another --ini or --configfile, --confidence-level,
        # --severity-level and --exclude token beside the ones already there.
        self._ini_file = None
        self._ini_warnings_given = set()
        self.args.extra_args = self._base_extra_args()
        from automated_security_helper.config.operator_only_options import (
            operator_wrote_value,
        )
        from automated_security_helper.config.path_trust import (
            derived_roots,
            refused_derived_product,
            resolved_path,
        )

        context_config = getattr(self.context, "config", None)
        source_dir = Path(getattr(self.context, "source_dir", None) or ".")
        configured = self.config.options.config_file
        configured_path = None
        refused_configured = False
        if configured is not None:
            # The option as the tool will read it: the file that passed the
            # check below is exactly the file handed over.
            config_file_path = resolved_path(configured, source_dir)
            if not config_file_path.is_file():
                # The path as the config gave it, which can be a value the config
                # read from the environment, and env values are never logged.
                from automated_security_helper.config.config_validator import (
                    redact_values,
                )
                from automated_security_helper.utils.error_text import (
                    config_environment_values,
                )

                shown = redact_values(
                    str(Path(configured)),
                    config_environment_values(context_config),
                )
                ASH_LOGGER.warning(
                    f"Configured bandit config file does not exist or is not a "
                    f"file: {shown}. Bandit will run with an empty ini file that "
                    "ASH writes; no config file is discovered from the scanned "
                    "tree in its place."
                )
            elif refused_derived_product(
                configured,
                source_dir=source_dir,
                key="scanners.bandit.options.config_file",
                config=context_config,
                derived_dirs=derived_roots(self.context),
                operator_written=operator_wrote_value(
                    context_config,
                    "scanner",
                    "bandit",
                    ("options", "config_file"),
                    configured,
                    config_from_context=self._config_from_context,
                ),
            ):
                refused_configured = True
            else:
                configured_path = config_file_path
        if refused_configured:
            # A configured value that was refused takes no discovered
            # replacement (config/path_trust.py, "Configured tool inputs that
            # are refused or missing"): bandit runs with an empty ini file.
            ASH_LOGGER.warning(
                "Configured bandit config file was not used because it is a "
                "work product derived from the scanned repository. Bandit will "
                "run with an empty ini file that ASH writes; no config file is "
                "discovered from the scanned tree in its place."
            )
        if configured_path is not None and Path(configured).name == ".bandit":
            # The ini-or-config decision follows the name the operator's
            # configuration gave, so a link named .bandit keeps its format.
            self._ini_file = configured_path
            self.args.extra_args.append(
                ToolExtraArg(key="--ini", value=configured_path.as_posix())
            )
        elif configured_path is not None:
            self.args.extra_args.append(
                ToolExtraArg(key="--configfile", value=configured_path.as_posix())
            )
        # With no operator .bandit, each scan passes an empty --ini ASH writes
        # for that scanner run (_execute_scan), so bandit never reads one from
        # the scanned tree, --configfile or not.

        self.args.extra_args.append(
            ToolExtraArg(
                key="--confidence-level", value=self.config.options.confidence_level
            )
        )
        self.args.extra_args.append(ToolExtraArg(key="--severity-level", value="all"))
        # bandit's --format is a single-valued argparse option (store): a second
        # --format after the base class's "--format sarif" won, bandit wrote that
        # format into bandit.sarif, and reading the results as SARIF failed the
        # scan. bandit cannot write two formats in one run, so none is added.
        not_produced = [
            fmt for fmt in self.config.options.additional_formats if fmt != "sarif"
        ]
        if not_produced:
            ASH_LOGGER.warning(
                text_without_values(
                    f"scanners.bandit.options.additional_formats names "
                    f"{not_produced}, but bandit writes one format per run and ASH "
                    "reads that run's output as SARIF, so these formats are not "
                    "produced. Convert the SARIF results with ASH's reporters.",
                    self._environment_values(),
                ),
                extra=NO_MARKUP,
            )
        if self.config.options.ignore_nosec:
            self.args.extra_args.append(ToolExtraArg(key="--ignore-nosec", value=None))

        required, _best_effort = self._configured_token_excludes(warn=True)
        self.args.extra_args.append(
            ToolExtraArg(key="--exclude=" + ",".join(required), value=None)
        )

        return super()._process_config_options()

    def _configured_token_excludes(self, warn: bool) -> Tuple[List[str], List[str]]:
        """The construction-time ``--exclude`` token's entries, for the source
        directory: ``_configured_excludes`` anchored there. Rebuilt per scan by
        ``_execute_scan``; this token only keeps the argument's shape visible."""
        anchor = Path(getattr(self.context, "source_dir", None) or ".")
        return self._configured_excludes(anchor, warn=warn), []

    def _configured_excludes(self, target: Path, warn: bool = False) -> List[str]:
        """The ``--exclude`` entries every scan of ``target`` gets: the known
        ignore paths, bandit's own default excludes (``BANDIT_DEFAULT_EXCLUDES``,
        which the explicit ``--exclude`` would otherwise replace) and bandit's
        ``excluded_paths`` (expired entries left out), anchored at the target
        (``bandit_excluded_path_globs``). ``warn`` names an entry that has no
        bandit form; the scanner passes it once, when it is built."""
        anchor = Path(target).as_posix()
        bandit_excludes = []
        for item in (*KNOWN_IGNORE_PATHS, *BANDIT_DEFAULT_EXCLUDES):
            bandit_excludes.extend(bandit_excluded_path_globs(anchor, item))
        # Redacted: the entries are configured, a configured value can come from
        # the environment, and ash.log keeps these lines (DEBUG under --debug).
        environment_values = self._environment_values()
        for item in active_ignore_paths(
            self.config.options.excluded_paths,
            where="scanners.bandit.options.excluded_paths",
        ):
            ASH_LOGGER.debug(
                text_without_values(
                    f"Path '{item.path}' excluded from {self.config.name} scan "
                    f"for reason: {item.reason}",
                    environment_values,
                ),
                extra=NO_MARKUP,
            )
            entries = bandit_excluded_path_globs(anchor, item.path)
            if warn and not entries:
                ASH_LOGGER.warning(
                    text_without_values(
                        f"bandit excluded_paths entry {item.path!r} has no bandit "
                        "--exclude form, so it excludes nothing: write a file, a "
                        "directory, or a glob without ',', a line break or a NUL, "
                        "and without '.' or empty path components.",
                        environment_values,
                    ),
                    extra=NO_MARKUP,
                )
            elif warn and _spelled_absolute(item.path):
                # The leading "/" is dropped and the rest read relative to the
                # scanned target, so a path that repeats the target's own
                # absolute prefix names nothing there; the operator was told
                # nothing and the entry excluded nothing.
                ASH_LOGGER.warning(
                    text_without_values(
                        f"bandit excluded_paths entry {item.path!r} is written as "
                        "an absolute path, but every entry is read relative to "
                        "the scanned target, so it is read as "
                        f"{item.path.replace(chr(92), '/').lstrip('/')!r} below "
                        "the target. Write the path relative to the target.",
                        environment_values,
                    ),
                    extra=NO_MARKUP,
                )
            bandit_excludes.extend(entries)
        return bandit_excludes

    def _scan_excludes(
        self, target: Path, global_ignore_paths: Sequence[IgnorePathWithReason]
    ) -> Tuple[List[str], List[str]]:
        """The ``--exclude`` entries for one scan of ``target``, as
        ``(required, best_effort)``.

        Anchored at the target as it appears in argv, since bandit matches each
        entry against ``os.path.join(root, name)`` while walking that string.
        ``required``: the known ignore paths and ``excluded_paths``
        (``_configured_excludes``), the operator's ``.bandit`` ``exclude`` entries
        anchored the same way (``_ini_excludes``), and each of ASH's output
        directories inside the target: this run's, and an earlier run's default
        ``.ash/ash_output``,
        the directories every other scanner that walks a directory skips
        (``_ash_output_dirs_inside``). Without them, a source tree holding
        ``.ash/ash_output`` had the converters' output scanned in the source pass
        as well as in the converted pass, and each of its findings reported twice.
        None is inside the converted target, which lives inside the output
        directory. ``best_effort``: globs for the live global ignore paths that
        bandit can be given without skipping a file they do not cover
        (``bandit_exclude_globs``), when the target is the source directory; the
        SARIF step applies every ignore path either way, so a caller may drop
        them under an argv bound. Any entry a file path under the target holds
        as text is left out of both (``_entries_no_path_holds_as_text``, one
        walk for the two sets).
        """
        anchor = Path(target).as_posix()
        excludes: List[str] = self._configured_excludes(target) + self._ini_excludes(
            target
        )
        # Ignore paths are relative to the source directory, so they are anchored
        # only when bandit is scanning it. Under the converted target the same
        # pattern names different files: "archive/**" would skip everything the
        # archive converter wrote, which the SARIF step keeps.
        ignore_globs: List[str] = []
        source_dir = getattr(self.context, "source_dir", None)
        if (
            source_dir is not None
            and Path(target).absolute() == Path(source_dir).absolute()
        ):
            for ignore_path in active_ignore_paths(global_ignore_paths):
                if _cannot_be_passed(ignore_path.path):
                    # Said, not swallowed: the entry gets no bandit form, so
                    # bandit reads the files it covers; the SARIF step drops
                    # their findings afterwards.
                    ASH_LOGGER.warning(
                        text_without_values(
                            f"Global ignore path {ignore_path.path!r} holds a line "
                            "break or a NUL character, which no --exclude entry can "
                            "carry, so bandit gets no entry for it and reads the "
                            "files it covers; their findings are dropped after the "
                            "scan.",
                            self._environment_values(),
                        ),
                        extra=NO_MARKUP,
                    )
                    continue
                ignore_globs.extend(bandit_exclude_globs(anchor, ignore_path.path))
        output_entries: List[Tuple[str, Path]] = []
        for relative in self._ash_output_dirs_inside(Path(target)):
            # The path as bandit spells it while walking the anchor, then the
            # separator and "*": bandit adds "/*" itself only to a value naming an
            # existing directory, which an escaped value does not.
            output_path = os.path.join(anchor, *relative.parts)
            if "," in output_path:
                ASH_LOGGER.warning(
                    f"Not excluding ASH's output directory {output_path} from "
                    "bandit: its --exclude value is comma-separated, and the path "
                    "has a comma. ASH drops bandit's findings there after the scan."
                )
                continue
            output_entries.append(
                (
                    escape_for_pattern(output_path, PatternSyntax.FNMATCH)
                    + os.sep
                    + "*",
                    relative,
                )
            )
        if not excludes and not ignore_globs and not output_entries:
            return [], []
        holding = _paths_holding_glob_characters(target)
        values = self._environment_values()
        required = _entries_no_path_holds_as_text(
            target, excludes, output_entries, holding=holding, values=values
        )
        best_effort = (
            _entries_no_path_holds_as_text(
                target,
                ignore_globs,
                [],
                holding=holding,
                values=values,
                level=logging.VERBOSE,
                applied_after_scan=True,
            )
            if ignore_globs
            else []
        )
        return required, best_effort

    def _ini_excludes(self, target: Path) -> List[str]:
        """``--exclude`` globs for the ``exclude`` setting of the operator's ``.bandit`` ini, anchored at ``target``.

        bandit 1.9.4 reads the ini's ``exclude`` only while its ``--exclude`` is
        still the default (``cli/main._log_option_source``), and ASH always
        passes one, so the operator's setting was silently ignored. bandit itself
        splits the value on ``,`` only, strips nothing, and tests each entry as
        an ``fnmatch`` glob or a plain substring of the walked path, unanchored
        (``core/manager.discover_files``). Passed that way under ASH, whose
        targets are absolute, an entry such as ``tests`` or ``build`` also
        matched a directory above the scanned tree and skipped every file, which
        the scanned-file check then graded SKIPPED. So each entry is anchored at
        the target as an ``excluded_paths`` entry is (``bandit_excluded_path_globs``):
        it names a path anywhere below the target and nothing above it, and an
        absolute entry is read relative to the target. An entry the builder has
        no form for (a line break, which a multi-line ini value holds, or a ``.``
        or empty component) is left out with a warning. An entry holding a NUL
        character, which no command-line argument can carry, is left out and
        counted in one warning. An entry that is text of
        the target's own path gets a warning that bandit alone would have skipped
        the whole tree. An entry with surrounding whitespace is passed as written,
        as bandit reads it, with a warning. An entry written as an absolute path
        is read relative to the target, as an ``excluded_paths`` entry is, with
        the same warning (``_spelled_absolute``). A plain name (no ``/``, no glob
        character), which bandit alone read as a substring of every walked path
        (``exclude = test`` skipped ``tests/``, ``test_x.py`` and ``testing/``
        too), is anchored as the exact name and the operator is told what it no
        longer covers. Each warning is about the operator's file, so it is given
        once per build, not once per scanned target, and the entry is written as
        its repr with the console markup off (``NO_MARKUP``: ``tests/[a-z]*`` is
        not a Rich tag). Only the operator's configured ``.bandit`` is read
        (``_process_config_options``); a file from the scanned tree never is. An
        ini that does not parse adds nothing, with a warning. Under a target whose
        own path holds a comma or a line feed no entry anchored at it can be
        passed at all, which ``_execute_scan`` says once for the target, so the
        entries are not blamed one by one here.
        """
        if self._ini_file is None:
            return []
        anchor = Path(target).as_posix()
        if "," in anchor or _holds_a_line_break(anchor):
            return []
        parser = configparser.ConfigParser()
        try:
            with open(self._ini_file, encoding="utf-8") as handle:
                parser.read_file(handle)
            raw = parser.get("bandit", "exclude", fallback="")
        except (OSError, UnicodeDecodeError, configparser.Error) as exc:
            self._warn_about_ini_once(
                "",
                "unreadable",
                f"Could not read the exclude setting of the configured .bandit "
                f"file, so bandit gets no entries from it: {type(exc).__name__}.",
            )
            return []
        entries: List[str] = []
        unpassable = 0
        for entry in raw.split(","):
            if not entry:
                continue
            if "\0" in entry:
                # No argument can carry a NUL; exec would refuse the whole
                # command line, and bandit would not start.
                unpassable += 1
                continue
            globs = bandit_excluded_path_globs(anchor, entry)
            if not globs:
                cause = (
                    "holds a line break"
                    if _holds_a_line_break(entry)
                    else "has a '.' or an empty path component, or names nothing"
                )
                self._warn_about_ini_once(
                    entry,
                    "no form",
                    f"The .bandit exclude entry {entry!r} {cause}, so it has no "
                    "--exclude form bandit can be given and excludes nothing.",
                )
                continue
            if entry != entry.strip():
                self._warn_about_ini_once(
                    entry,
                    "whitespace",
                    f"The .bandit exclude entry {entry!r} has surrounding "
                    "whitespace, which bandit reads as part of the entry; it is "
                    "passed as written.",
                )
            spelled = entry.replace("\\", "/")
            if _spelled_absolute(entry):
                self._warn_about_ini_once(
                    entry,
                    "absolute",
                    f"The .bandit exclude entry {entry!r} is written as an absolute "
                    "path, but every entry is read relative to the scanned target, "
                    f"so it is read as {spelled.lstrip('/')!r} below the target. "
                    "Write the path relative to the target.",
                )
            elif "/" not in spelled and not _GLOB_CHARACTERS & set(entry):
                self._warn_about_ini_once(
                    entry,
                    "plain name",
                    f"The .bandit exclude entry {entry!r} is a plain name, which "
                    "bandit alone reads as a substring of every walked path, so it "
                    f"also skipped names that merely contain it ({entry}s/, "
                    f"{entry}_x.py). ASH passes it as the exact name {entry!r} at "
                    f"any depth below the target; write a glob ({entry}*) to keep "
                    "the wider reading.",
                )
            if entry in anchor:
                self._warn_about_ini_once(
                    entry,
                    "own path",
                    f"The .bandit exclude entry {entry!r} is part of the scanned "
                    f"target's own path {anchor}: bandit alone reads an entry as a "
                    "substring of every walked path and would have skipped the "
                    "whole tree. ASH applies it below the target only.",
                )
            entries.extend(globs)
        if unpassable:
            self._warn_about_ini_once(
                "",
                "nul",
                f"{unpassable} exclude entries of the configured .bandit file hold "
                "a NUL character, which no command-line argument can carry; "
                "bandit gets no entry for them.",
            )
        return entries

    def _warn_about_ini_once(self, entry: str, subject: str, message: str) -> None:
        """Warn about a ``.bandit`` exclude ``entry`` once per build.

        ``_ini_excludes`` runs for every scanned target (the source and the
        converted one), and its warnings describe the operator's file, so a
        warning given for one target is not given again for the next; the key
        is the entry and what the warning is about. The entry is written in the
        message as its repr, and the console markup is off (``NO_MARKUP``), so
        an entry such as ``tests/[a-z]*`` is not read as a Rich tag.
        """
        key = (entry, subject)
        if key in self._ini_warnings_given:
            return
        self._ini_warnings_given.add(key)
        ASH_LOGGER.warning(message, extra=NO_MARKUP)

    # Bandit emits exit code 1 when findings are present; treat that as success
    # alongside 0. (Same as base default, but spelled out for clarity.)
    success_exit_codes: ClassVar[set] = {0, 1}

    # Python-only repos commonly have empty target dirs after conversion;
    # log at VERBOSE rather than INFO to keep the user-facing output clean.
    empty_target_log_level: ClassVar[int] = logging.VERBOSE

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: Any = None,
        *args,
        **kwargs,
    ) -> Any:
        """The template scan, with this target's scanned-file count reset first.

        ``targets_attempted`` is set from bandit's SARIF (_record_scanned_files) and
        read by the executor after every target, so a target that returns before
        bandit runs (an empty directory) must not keep the last one's.
        """
        self.targets_attempted: Optional[int] = None
        return super().scan(
            target, target_type, global_ignore_paths, config, *args, **kwargs
        )

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        """Resolve final argv and results path for Bandit.

        The ``--exclude`` token built at construction is swapped, for this
        resolution only, for one that also carries this scan's entries
        (``_scan_excludes``) and the links leaving ``target``
        (``_link_excludes``); the scanner's own arguments are restored
        afterwards, so repeated scans do not accumulate them. Built only at
        construction, the token would miss the global ignore paths, which are
        merged here while ``_resolve_arguments`` runs: resolution does not
        rebuild the token.

        The value is bounded to what the command line can carry
        (``_exclude_fits``: one argument of 120 KiB where arguments are bounded
        one by one, the whole 32,767-character line on Windows): the configured,
        output-directory and link entries have to fit, or bandit is not run on
        ``target`` (over the bound it would read the file a link points at, or
        exec would fail with E2BIG and blame nothing); the global-ignore globs
        are added while they fit and dropped with a warning past it, since the
        SARIF step applies every ignore path after the scan either way. The
        bound is measured on the resolved command, so the budget on Windows is
        what the other arguments leave.
        """
        target_results_dir = self.results_dir.joinpath(target_type)
        results_file = target_results_dir.joinpath("bandit.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)

        if _holds_a_line_break(Path(target).as_posix()):
            # Every entry is anchored at the target, and the builders refuse an
            # anchor that holds a line break, so bandit would get no exclusion
            # at all for such a target: not the default excludes, not the
            # output directory inside the tree, not the links that leave it.
            raise ScannerError(
                f"Not running bandit on {Path(target).as_posix()!r}: its path "
                "holds a line break, which no --exclude entry anchored at it can "
                "carry, so bandit would run with no exclusion at all."
            )
        if "," in Path(target).as_posix():
            # bandit splits --exclude on commas, so no entry anchored at this
            # target can be passed (the builders return none): not the known
            # ignore paths, not bandit's default excludes, not excluded_paths.
            # A link that leaves the tree still refuses the scan
            # (_link_excludes). The rest ran silently with an empty --exclude.
            self._plugin_log(
                f"The path of {Path(target).as_posix()!r} holds a comma, which "
                "bandit's comma-separated --exclude cannot carry, so no "
                "exclusion anchored at it is passed: bandit reads the known "
                "ignore paths, its own default excludes and the excluded_paths "
                "entries under it. The findings the ignore paths cover are "
                "dropped after the scan; the excluded_paths entries apply to "
                "nothing.",
                target_type=target_type,
                level=logging.WARNING,
            )
        files, links = walked_files(target)
        required, best_effort = self._scan_excludes(target, global_ignore_paths or [])
        entries = required + self._link_excludes(target, files=files, links=links)
        if any(_holds_a_line_break(entry) for entry in entries):
            # The base class drops a flag key that holds a line break, which here
            # is the whole --exclude: bandit would then read every excluded file,
            # the links that leave the tree included. The entries' own text is
            # checked by their builders, so what is left is the target's path or
            # an output directory inside it.
            raise ScannerError(
                f"Not running bandit on {Path(target).as_posix()}: its --exclude "
                "value would hold a line break (in the target's path or an output "
                "directory inside it), which one command-line argument cannot "
                "carry, so bandit would run with no exclusion at all."
            )
        # A new list: the one extra_args holds is put back as it was, unchanged.
        original_extra_args = self.args.extra_args
        resolution_args = [
            arg for arg in original_extra_args if not arg.key.startswith("--exclude=")
        ]
        if self._ini_file is None:
            # Given no --ini, bandit walks its targets for a .bandit file, which
            # can set skips and exclude. The --ini is an empty file ASH writes
            # for this scanner run, outside the scanned tree and removed when
            # the run ends (config/tool_config_trust.empty_tool_config), never
            # the results directory, which the default layout puts inside the
            # tree.
            resolution_args.append(
                ToolExtraArg(
                    key="--ini",
                    value=empty_tool_config(
                        "bandit-empty.ini", "[bandit]\n", context=self.context
                    ).as_posix(),
                )
            )
        # Resolved with the required entries first: the bound is measured on
        # the whole command, so the other arguments have to be known before the
        # token can be judged and the best-effort globs added to it.
        token = f"--exclude={','.join(entries)}"
        self.args.extra_args = resolution_args + [ToolExtraArg(key=token, value=None)]
        try:
            final_args = self._resolve_arguments(
                target=target, results_file=results_file
            )
        finally:
            self.args.extra_args = original_extra_args

        token_index = next(
            (
                index
                for index, argument in enumerate(final_args)
                if str(argument).startswith("--exclude=")
            ),
            None,
        )
        if token_index is None:
            raise ScannerError(
                f"Not running bandit on {Path(target).as_posix()}: its --exclude "
                "argument was not placed in the command line, so bandit would run "
                "with no exclusion at all."
            )
        rest = [str(argument) for argument in final_args]
        del rest[token_index]
        if not _exclude_fits(token, rest):
            raise ScannerError(
                f"Not running bandit on {Path(target).as_posix()}: its --exclude "
                f"value, with the {len(links)} links that leave the scanned tree, "
                f"does not fit {_command_line_bound_text()}."
            )
        left_out = 0
        for index, entry in enumerate(best_effort):
            candidate = f"{token},{entry}" if entries else f"--exclude={entry}"
            if not _exclude_fits(candidate, rest):
                # End at the first entry that does not fit, rather than go on
                # trying every shorter one: that filled the line to within a few
                # characters of the bound, which left nothing for what the
                # measured line does not hold (the uv wrapper on Windows).
                left_out = len(best_effort) - index
                break
            entries.append(entry)
            token = candidate
        if left_out:
            self._plugin_log(
                f"{left_out} globs for the global ignore paths are not in bandit's "
                f"--exclude, which would not fit {_command_line_bound_text()}; "
                "bandit reads the files they cover, and ASH drops their findings.",
                target_type=target_type,
                level=logging.WARNING,
            )
        final_args[token_index] = token

        return final_args, results_file, None

    def _link_excludes(
        self,
        target: Path,
        files: List[str] | None = None,
        links: List[str] | None = None,
    ) -> List[str]:
        """``--exclude`` entries for each link to a file whose target leaves ``target``.

        bandit reads a link to a file wherever it points: its walk lists the link
        among the files and opens it by name. The links come from
        ``file_links_leaving_tree``, which walks as bandit does (``os.walk``, which
        does not descend links to directories) and ignores ignore files, as bandit
        does.

        bandit 1.9.4 (``bandit/core/manager.py``) splits ``--exclude`` on commas and
        leaves out a walked file when an entry matches its path with ``fnmatch`` or
        is a substring of it. So each entry names the link's path as bandit's walk
        spells it, ``<target>/<path below it>``, as a glob that matches that one
        path and is a plain substring of no ordinary path: its glob characters
        escaped (``glob.escape``), else its last character bracketed
        (``_not_a_plain_substring``, as the ignore-path globs are). The literal
        path was passed before, and refused whenever another file's path held it
        as text: ``<root>/.venv/bin/python`` is a substring of
        ``<root>/.venv/bin/python3``, so every tree with a symlinked virtualenv
        was refused. Written as ``<root>/.venv/bin/pytho[n]`` it matches
        ``python`` alone, and as text it occurs only in a path that has a ``[``.

        An entry is used only when it leaves out that file alone: it holds no
        comma and no line break (bandit splits on the one; the other cannot be
        passed, see ``_holds_a_line_break``), and no other file's path under
        ``target`` holds its glob form as text.

        ``files`` and ``links`` are ``walked_files(target)``, when the caller has
        walked it already.

        Raises:
            ScannerError: Naming the first link that cannot be left out that way,
                or the first link at all when walked paths are not joined with
                ``/`` (Windows). bandit is then not run on ``target``, rather than
                read the file the link points at.
        """
        if files is None or links is None:
            files, links = walked_files(target)
        if not links:
            return []
        root = Path(target).as_posix()
        walked = [f"{root}/{relative}" for relative in files]
        entries = []
        for relative in links:
            entry = f"{root}/{relative}"
            if os.sep != "/" or any(
                character in entry for character in _BANDIT_EXCLUDE_UNSAFE
            ):
                raise ScannerError(
                    f"Not running bandit on {root}: {relative!r}: "
                    f"{REASON_LINK_LEAVES_TREE}, and bandit's --exclude cannot leave "
                    "out that file alone, so bandit would read the file it points at."
                )
            spelled = glob.escape(entry)
            if spelled == entry:
                bracketed = _not_a_plain_substring(entry)
                if bracketed is None:
                    # Only when the whole "<root>/<path>" is made of "/!^-]":
                    # the root's own characters are bracketed otherwise, so a
                    # link named "-" under an ordinary root keeps its entry.
                    raise ScannerError(
                        f"Not running bandit on {root}: {relative!r}: "
                        f"{REASON_LINK_LEAVES_TREE}, and bandit's --exclude cannot "
                        "leave out that file alone, so bandit would read the file "
                        "it points at."
                    )
                spelled = bracketed
            if any(spelled in other for other in walked if other != entry):
                raise ScannerError(
                    f"Not running bandit on {root}: {relative!r}: "
                    f"{REASON_LINK_LEAVES_TREE}, and another file's path under the "
                    "target contains its --exclude entry as text, so bandit would "
                    "skip that file too or read the file the link points at."
                )
            if os.path.isdir(spelled):
                # bandit rewrites an entry that names an existing directory to
                # "<entry>/*" (manager.discover_files), so a directory literally
                # named like the glob ("lin[k].py" beside "link.py") would turn
                # the entry into one that covers that directory and no longer
                # matches the link, and bandit would read the file it points at.
                # The ignore entries are checked the same way
                # (_entries_no_path_holds_as_text, named_directories).
                raise ScannerError(
                    f"Not running bandit on {root}: {relative!r}: "
                    f"{REASON_LINK_LEAVES_TREE}, and a directory under the target "
                    "is named like its --exclude entry, which bandit would rewrite "
                    "to cover that directory instead, so bandit would read the "
                    "file the link points at."
                )
            entries.append(spelled)
        return entries

    def _invocation_extras(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> dict:
        """bandit's ``toolConfigurationNotifications``, carried into ASH's invocation.

        The base replaces ``runs[0].invocations`` with one ASH ``Invocation``
        before ``_post_process_sarif`` runs, and carries over only the tool's
        ``toolExecutionNotifications``. bandit names the files it could not parse
        in ``toolConfigurationNotifications`` (``formatters/sarif
        .add_skipped_file_notifications``, 1.9.4), so with them dropped the
        skipped set ``_record_scanned_files`` read was always empty in a real
        scan, and a target whose every Python file failed to parse was still
        graded PASSED with zero findings.
        """
        notifications: List[Any] = []
        for own in sarif_report.runs[0].invocations or []:
            notes = getattr(own, "toolConfigurationNotifications", None)
            if notes:
                notifications.extend(notes)
        if not notifications:
            return {}
        return {"toolConfigurationNotifications": notifications}

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Record how many files bandit scanned, and mask secret-shaped strings."""
        self._record_scanned_files(sarif_report, final_args, target)
        return mask_secrets_in_sarif(sarif_report)

    def _record_scanned_files(
        self, sarif_report: SarifReport, final_args: List[str], target: Path
    ) -> None:
        """Set ``targets_attempted`` from the files bandit's SARIF lists.

        bandit's SARIF carries ``run.properties.metrics``: ``_totals`` and one entry
        per file it opened. A file it could not parse (a syntax error) keeps its
        metrics entry, with nothing counted, and is named in the run's
        ``invocations[].toolConfigurationNotifications`` (bandit 1.9.4,
        ``formatters/sarif.add_skipped_file_notifications``); such a file was not
        scanned, so it is not counted, and a target whose every Python file failed
        to parse is not graded PASSED with zero findings. None scanned while the
        target holds ``.py`` or ``.pyw`` files bandit was not told to exclude
        (matched as bandit 1.9.4 matches its ``--exclude`` entries, by ``fnmatch``
        or as a substring) means its result says nothing about them: an error, not
        a PASSED with no findings. None scanned and none there is SKIPPED
        (``targets_attempted`` 0). No metrics leaves the count unset (no claim).

        Raises:
            ScannerError: When bandit scanned no file of the Python files there.
        """
        scanned = None
        for run in sarif_report.runs or []:
            properties = run.properties.model_dump() if run.properties else {}
            metrics = properties.get("metrics")
            if isinstance(metrics, dict):
                skipped = _skipped_file_paths(run)
                scanned = (scanned or 0) + sum(
                    1
                    for key in metrics
                    if key != "_totals"
                    and _spelled_path(str(key), uri=False) not in skipped
                )
        if scanned is None:
            return
        if scanned:
            self.targets_attempted = scanned
            return
        prefix = "--exclude="
        entries = [
            entry
            for arg in final_args
            if str(arg).startswith(prefix)
            for entry in str(arg)[len(prefix) :].split(",")
            if entry
        ]
        # The operator's --configfile can set bandit's include globs and
        # exclude_dirs, which bandit applies before --exclude: a config that
        # legitimately leaves every Python file out was read as "scanned no file".
        include_globs, exclude_dirs = _config_file_filters(final_args)
        root = Path(target).as_posix()
        for entry in exclude_dirs:
            if entry in root:
                # bandit alone reads an exclude_dirs entry as a substring of every
                # walked path, so an entry that is part of the target's own path
                # ("tests" under a tree at .../tests-infra/repo) skipped the
                # whole tree. Read as an exclusion here, that made the target
                # SKIPPED with no word; it is said, and left out, so the files it
                # hid count as unexcluded and the result is graded as it was: an
                # error, since bandit's result says nothing about them. The ini
                # exclude entries warn the same way (_ini_excludes).
                ASH_LOGGER.warning(
                    f"The bandit config file's exclude_dirs entry {entry!r} is part "
                    f"of the scanned target's own path {root}: bandit reads an "
                    "entry as a substring of every walked path and skipped the "
                    "whole tree, so its result says nothing about the files there.",
                    extra=NO_MARKUP,
                )
                continue
            entries.append(entry)
        all_files, _ = walked_files(target)
        python = [
            f"{root}/{relative}"
            for relative in all_files
            if any(
                fnmatch.fnmatch(f"{root}/{relative}", glob_pattern)
                for glob_pattern in include_globs
            )
        ]
        unexcluded = [
            path
            for path in python
            if not any(fnmatch.fnmatch(path, e) or e in path for e in entries)
        ]
        if unexcluded:
            raise ScannerError(
                f"bandit scanned no file below {root}, though {len(unexcluded)} Python "
                "files there are not excluded, so its result says nothing about them."
            )
        self.targets_attempted = 0


if __name__ == "__main__":
    # As npm_audit's block does: a scanner needs a context, and run as a script its
    # class resolves its "AshConfig" reference only once that name is bound here.
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    AshConfig.model_rebuild()
    ASH_LOGGER.debug("Running Bandit via __main__")
    scanner = BanditScanner(
        context=PluginContext(
            source_dir=Path.cwd(),
            output_dir=Path.cwd().joinpath(".ash", "ash_output"),
        ),
        config=BanditScannerConfig(
            options=BanditScannerConfigOptions(
                confidence_level="all",
                severity_threshold="ALL",
                ignore_nosec=False,
                excluded_paths=[],
                additional_formats=[],
            )
        ),
    )
    report = scanner.scan(target=Path("."), target_type="source")

    if isinstance(report, SarifReport):
        from automated_security_helper.utils.command_safe_stream import (
            json_commands_broken,
        )
        from automated_security_helper.utils.console import echo_raw

        # The SARIF repeats the tree's file names: no "##name[" of theirs is a
        # CI command where this prints, and the JSON is still the same document.
        echo_raw(
            json_commands_broken(
                report.model_dump_json(
                    indent=2,
                    by_alias=True,
                    exclude_unset=True,
                )
            )
        )
