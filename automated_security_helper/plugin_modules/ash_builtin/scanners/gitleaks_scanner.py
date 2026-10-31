# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitleaks secret scanner, as a builtin scanner.

What it runs
------------
``gitleaks dir`` over the scan target: the files as they are on disk, not git
history. History scanning (``gitleaks git``) answers a different question --
"was a secret ever committed" -- and its findings point at commits rather than
at lines a reader can open, which none of ASH's suppression or reporting paths
understand. It also needs a full clone, which most CI checkouts are not. ASH's
other secret scanner, detect-secrets, scans the working tree too, so both answer
the same question and their findings line up file for file.

Every invocation carries these flags, and none of them is configurable:

* ``--redact=100``: gitleaks writes ``REDACTED`` in place of every secret value,
  in its SARIF snippet and in its log. ASH's own ``utils/secret_masking.py``
  only knows bandit's password rules, so it does not cover gitleaks findings;
  the redaction has to happen in the tool. ``_post_process_sarif`` also
  overwrites any snippet that is not ``REDACTED``, so a future gitleaks that
  added the match to its SARIF still could not put a secret in ASH's outputs.
  Written with ``=`` because gitleaks declares ``--redact`` with an optional
  value: ``--redact 100`` would make ``100`` the scan path.
* ``--exit-code=2``: gitleaks exits 1 both when it finds leaks (its default
  ``--exit-code``) and when it fails (every fatal log line exits 1, including an
  unreadable config). Moving the leaks code to 2 is the only way to tell those
  apart, so 0 and 2 are success and 1 is a failure. Each target (the source, then
  the converted files) is judged by its own run's exit code.
* ``--no-banner``, ``--no-color``: the log goes to a file nobody reads in a
  terminal.
* ``--gitleaks-ignore-path=<empty directory ASH makes>``: by default gitleaks
  reads ``.gitleaksignore`` from its working directory, the source directory.
  The directory, like ASH's default-rules config below, is new for each run,
  outside the scanned tree, and removed when the run ends
  (``config/tool_config_trust``).

The scanned repository's own gitleaks configuration is not used
---------------------------------------------------------------
A ``.gitleaks.toml`` can replace gitleaks' rules or allowlist any path, and a
``.gitleaksignore`` or a baseline report drops findings by fingerprint. gitleaks
applies all of them before ASH sees a result, so what they hide is neither
reported nor counted as suppressed. Findings are tuned with ASH suppressions,
which are both, so the scanned tree does not configure gitleaks:

* The config is the operator's ``options.config_file`` (set by
  ``--config-overrides`` or a config file outside every git checkout and the
  scanned directory, ``utils/config_trust.py``), else ``GITLEAKS_CONFIG`` or ``GITLEAKS_CONFIG_TOML``
  from the operator's environment (outside the scanner sandbox, which does not
  pass them in), else a config ASH writes that extends gitleaks' default rules and
  adds nothing. It is passed as ``--config`` in every case but one, so gitleaks
  never falls through to ``<target>/.gitleaks.toml``: an absolute
  ``GITLEAKS_CONFIG``, or ``GITLEAKS_CONFIG_TOML``, is left to gitleaks, which
  reads the variable itself; a ``GITLEAKS_CONFIG`` that is not absolute as given
  (``rules.toml``, ``~/rules.toml``) is anchored to the directory ASH runs in and
  passed as ``--config``, because gitleaks would resolve it against its working
  directory, the scanned tree. A
  ``config_file`` or ``baseline_path`` set by a config inside a git checkout or the
  scanned directory is ignored with a warning, and a ``.gitleaks.toml`` or ``.ash/.gitleaks.toml`` in
  the tree with a note. An operator's file that does not exist fails the scan
  rather than falling back to the default rules.
* ``.gitleaksignore``: gitleaks reads ``<scan path>/.gitleaksignore`` whatever
  ``--gitleaks-ignore-path`` says, and has no flag to turn that off (measured on
  8.30.1). When the scan root has one, ASH copies the files it names into a
  directory of its own outside the scanned tree, in the scanner run's own
  directory (``config/tool_config_trust.empty_tool_directory``), at their paths
  relative to the root, runs gitleaks once
  more over that directory (no ``.gitleaksignore`` is there), and adds back every
  finding the first run dropped. gitleaks walks the copies under the same
  relative paths, so the directories its allowlists skip (``.git``, by default)
  are skipped there too, and ASH copies nothing the walk would not read: no file
  reached through a symlink, nothing that is not a regular file, nothing ASH
  wrote under its output directory, not the operator's baseline. A failed re-run
  fails the scan rather than reporting the first run alone, and the copies are
  removed when it ends. It copies at most ``MAX_RESCAN_FILES`` files and
  ``MAX_RESCAN_BYTES`` bytes (a file that does not fit is skipped and the names
  after it are still tried), reads at most ``MAX_IGNORE_CANDIDATES`` names from
  the ignore file, and its copies and runs share one ``scan_timeout``; files
  and names not reached are reported as not evaluated, which makes the scan
  incomplete.
* Inline ``gitleaks:allow`` comments drop a finding the same way, so ASH passes
  ``--ignore-gitleaks-allow``. ``options.honor_inline_ignores: true`` turns them
  back on; it is honored only when the operator set it, and from a config inside a
  git checkout or the scanned directory it is ignored with a warning.
* A ``.gitleaksignore`` that is a symlink to a file, not a regular file, or
  hard-linked stops the scanner before gitleaks runs
  (``_read_tree_ignore_file``): gitleaks opens the name, follows the link, and
  logs each line it cannot parse. ASH reads the file once, without following a
  link, and parses what it read. A link to a directory, or one that leads
  nowhere, is read as no ignore file, since gitleaks reads no line through
  either. gitleaks' log is never quoted in an error, and the lines in it that
  quote the file are cut (``_mask_quoted_ignore_entries``). The file is read
  again after gitleaks ran, and a change between the two reads fails the scan:
  the re-scan would otherwise cover entries other than the ones gitleaks
  applied.

Paths
-----
The source target is passed as ``.`` with the working directory at the source
directory, so gitleaks reports paths like ``src/settings.py``. That is the form
``.gitleaksignore`` fingerprints are written in (``<file>:<rule>:<line>``), so a
fingerprint file written against a plain ``gitleaks dir .`` run keeps working
under ASH. The converted target is passed as an absolute path, as every other
scanner receives it.

ASH's output directory is not excluded at the tool. gitleaks has no exclude
flag, and the only route -- a generated config that extends the user's -- would
take over the config precedence above. So when the output directory is inside
the source target (the default ``.ash/ash_output``), gitleaks reads it, and
``_post_process_sarif`` drops every source-run finding under it, as
detect-secrets, zizmor and actionlint leave it out of the files they scan. A
finding in a file the repository committed there is kept: that file is the
tree's, not ASH's output. ``committed_output_files`` names those files, as it
does for the executor's drop and the suppression step (``_committed_file_test``).
Outside a git checkout, and where git cannot say what is tracked, nothing tells
the two apart, and every file under the output directory is treated as ASH's.
``apply_suppressions_to_sarif`` is not enough on its own: it keeps findings under
``work_dir`` (``<output>/converted``), where the converted target's findings
live, and the source run reads the same converted copies of archives and
notebooks that the converted run reports, so one secret would be two findings.

Severity
--------
gitleaks SARIF results carry no ``level`` (measured on 8.30.1). Every gitleaks
result is set to ``level: error`` and ``issue_severity: CRITICAL``. ASH reads a
bare ``error`` two ways (the summary and the scan gate as CRITICAL, the flat
reporters such as flat JSON and CSV as HIGH), and every reader honors
``issue_severity``, so with both set each report says CRITICAL, as cfn-lint and
cfn-guard do for theirs.

It is set rather than left to ASH's SARIF model, whose ``Result.level``
defaults to "error" too. A default is not a set field, so the ``exclude_unset``
dump ASH writes its SARIF with drops it, and whoever reads that file applies the
SARIF spec's default for an absent level instead, which is "warning". gitleaks has no per-rule confidence to grade on: every rule is "a
credential of this kind is present", and an exposed credential is the same
severity whichever provider issued it.
"""

import json
import logging
import os
import posixpath
import shutil
import stat
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import (
    Annotated,
    Any,
    BinaryIO,
    Callable,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.tool_config_trust import (
    empty_tool_config,
    empty_tool_directory,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Invocation,
    Kind,
    Level,
    Message,
    Message1,
    Notification,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.utils.config_trust import (
    LEADS_OUT_OF_THE_TREE,
    operator_path,
    refusal_warning,
    set_by_operator,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import active_scope
from automated_security_helper.utils.scan_output_dirs import committed_output_files
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)

#: The text gitleaks writes in place of a secret under ``gitleaks --redact``.
REDACTED = "REDACTED"

#: Exit code gitleaks is told to use when it finds leaks. See the module docstring.
LEAKS_EXIT_CODE = 2

#: The clock the re-scan deadline reads. A test replaces this name, not
#: ``time.monotonic``, which every thread in the process reads.
_monotonic = time.monotonic

#: gitleaks config names a repository commits. ASH does not read them from the
#: scanned tree; they are named only in the note logged when one is present.
TREE_CONFIG_NAMES = (".gitleaks.toml", ".ash/.gitleaks.toml")

#: Environment variables gitleaks reads a config from. When either is set, outside
#: the scanner sandbox, ASH passes no ``gitleaks --config`` and gitleaks reads the
#: variable; a non-absolute ``GITLEAKS_CONFIG`` is anchored to the directory ASH
#: runs in and passed as ``gitleaks --config``, so the scanned tree cannot supply it.
CONFIG_ENV_VARS = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")

#: The ignore file gitleaks always reads at the root of its scan path.
IGNORE_FILE_NAME = ".gitleaksignore"

#: The directory the re-scan's copies are made in, in the scanner run's own
#: directory outside the scanned tree. Its re-scan reports and logs are written
#: under the results directory, in a directory of the same name.
RESCAN_DIR_NAME = "gitleaksignore-rescan"

#: Under the copies directory: the copies of the files ``.gitleaksignore``
#: names, at their tree paths, and the copy of ``.gitleaksignore`` itself when it
#: names itself. See ``GitleaksScanner._copy_for_rescan``.
RESCAN_TREE_DIR = "tree"
RESCAN_SELF_DIR = "self"

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)

#: Most files the ``.gitleaksignore`` re-scan copies. Names past it are not
#: re-scanned, and the run reports them as not evaluated, which fails the scan
#: as incomplete (``run_ash_scan.unevaluated_rules``).
MAX_RESCAN_FILES = 10_000

#: Most bytes the ``.gitleaksignore`` re-scan copies in all. The copies go to
#: the run's own directory, under TMPDIR by default, and a tree could otherwise
#: have ASH duplicate gigabytes there by naming large files. A file that would
#: take the total past this is not re-scanned and is reported as not evaluated,
#: as names past ``MAX_RESCAN_FILES`` are; the names after it are still tried,
#: so one large file does not leave the smaller ones that fit un-scanned. The cap
#: has no option: raising it is a decision about the disk the copies use.
MAX_RESCAN_BYTES = 1 << 30

#: Most bytes of the tree's ``.gitleaksignore`` ASH reads. A larger file stops
#: the scan: its entries could not all be re-scanned.
MAX_IGNORE_FILE_BYTES = 32 * 1024 * 1024

#: Longest candidate file name taken from a ``.gitleaksignore`` line, in characters:
#: Linux's ``PATH_MAX`` (macOS's is 1024), or the extended-length limit on
#: Windows. A longer prefix names no file, so it is never built.
MAX_CANDIDATE_LENGTH = 32_767 if os.name == "nt" else 4_096

#: Longest last component of a candidate: ``NAME_MAX``, 255 of the unit the
#: platform's file systems count in (``NAME_MAX_IN_UTF16``).
MAX_NAME_LENGTH = 255

#: Whether a file name is bounded in UTF-16 code units, as NTFS bounds it, or in
#: UTF-8 bytes, as Linux and APFS bound it. A name of 100 CJK characters is 100
#: units and 300 bytes: a valid Windows name that a byte count would drop.
NAME_MAX_IN_UTF16 = os.name == "nt"

#: Most candidate names, and most characters in all, taken from the tree's
#: ``.gitleaksignore``. One line splits at every colon, so a few lines of colons
#: could otherwise make gigabytes of strings before the re-scan's deadline is
#: set. What is left unread is reported as names not evaluated, which fails the
#: scan as incomplete (``run_ash_scan.unevaluated_rules``).
MAX_IGNORE_CANDIDATES = 100_000
MAX_IGNORE_CANDIDATE_CHARS = 64 * 1024 * 1024

#: The characters Go's ``unicode.IsSpace`` reports as space, which
#: ``strings.TrimSpace`` strips from both ends of each ``.gitleaksignore`` line:
#: Unicode's White_Space property. Python's ``str.strip()`` strips more (U+001C
#: to U+001F), so it would read a different file name than gitleaks does.
_GO_SPACE = (
    "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)

#: ``bufio.MaxScanTokenSize``. gitleaks reads ``.gitleaksignore`` with a
#: ``bufio.Scanner``, which stops at the first line it cannot hold with its
#: newline in a buffer this size; ``AddGitleaksIgnore`` does not check the error,
#: so the rest of the file is silently not applied.
_MAX_SCAN_TOKEN = 64 * 1024

#: What gitleaks logs, at WRN, before each ``.gitleaksignore`` line it cannot
#: parse, which it then quotes. ``_mask_quoted_ignore_entries`` drops the quote.
INVALID_ENTRY_LOG = "Invalid .gitleaksignore entry"

#: The config ASH passes when the operator chose none: gitleaks' default rules.
DEFAULT_RULES_CONFIG = (
    "# Written by ASH: gitleaks' default rules and nothing else, so no gitleaks\n"
    "# config in the scanned tree is read.\n"
    "[extend]\n"
    "useDefault = true\n"
)


def _write_private_copy(source: BinaryIO, destination: Path) -> None:
    """Copy ``source`` to a new file at ``destination``, readable by its owner only.

    ``O_EXCL`` and ``O_NOFOLLOW``: the file must not exist, so nothing at its name
    in the copies directory can redirect the write. The copy holds the tree's
    secrets until the re-scan removes it.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY,
        0o600,
    )
    with os.fdopen(fd, "wb") as out:
        shutil.copyfileobj(source, out)


def _name_length(name: str) -> int:
    """``name``'s length in the unit this platform bounds a file name in.

    UTF-16 code units where ``NAME_MAX_IN_UTF16`` (a character outside the Basic
    Multilingual Plane is two), UTF-8 bytes elsewhere. The name was decoded with
    ``surrogateescape``, so an undecodable byte is one lone surrogate: one unit
    here, and the one byte it was in the byte count.
    """
    if NAME_MAX_IN_UTF16:
        return len(name.encode("utf-16-le", "surrogatepass")) // 2
    return len(name.encode("utf-8", "surrogateescape"))


def gitleaksignore_files(data: bytes) -> List[str]:
    """The candidate files of ``gitleaksignore_candidates``, without the count left unread."""
    return gitleaksignore_candidates(data)[0]


def gitleaksignore_candidates(data: bytes) -> Tuple[List[str], int]:
    """The file part of each fingerprint in ``data``, as gitleaks 8.30.1 reads it.

    ``Detector.AddGitleaksIgnore`` (``detect/detect.go`` at v8.30.1) reads the
    file with a ``bufio.Scanner`` (``ScanLines``: lines end at ``\n`` alone, one
    trailing ``\r`` dropped, reading stops at a line of 64 KiB or more), trims each
    line with ``strings.TrimSpace``, skips empty lines and lines starting with
    ``#``, splits on ``:`` and replaces ``\\`` with ``/`` in the file part: the
    first of three parts, or the second of four (``commit:file:rule:line``). The
    rejoined line is matched exactly against each finding's
    ``<file>:<rule>:<line>`` (``AddFinding``), so where the ``:`` between the
    file and the rule falls is not in the line: a rule id can hold ``:`` (an
    operator's config names rules freely), and then the file is not everything
    before the last two ``:``. Every split that leaves a rule and a line is
    returned as a candidate file; one that names no file in the tree is skipped
    where the files are copied (``_copy_for_rescan``), and one that names a file
    the line did not hide costs a copy whose findings the first run already
    reported. A line with fewer than three parts can hide nothing.

    Bytes are decoded with ``surrogateescape``, so a name that is not UTF-8 maps
    back to the same bytes on disk.

    Returns the candidates and the number of candidates left unread. The
    candidates are bounded, because one line of ``a:`` repeated up to the 64 KiB
    a line may hold splits at every colon and the prefixes are quadratic in its
    length (about a gigabyte of strings for one such line, with hundreds allowed
    in the file), all from the scanned tree's own text and before the re-scan's
    deadline is set. A prefix no file can have is never made (longer than
    ``MAX_CANDIDATE_LENGTH``, or ending in a component longer than
    ``MAX_NAME_LENGTH``), a name is returned once however many lines repeat it,
    and reading stops when ``MAX_IGNORE_CANDIDATES`` distinct names or
    ``MAX_IGNORE_CANDIDATE_CHARS`` characters have been made. What is left,
    counted by the colons of the lines not read, is the second value; the caller
    reports it as names not evaluated, so the scan fails as incomplete.
    """
    files: List[str] = []
    seen: Set[str] = set()
    unread = 0
    characters = 0
    for raw in data.split(b"\n"):
        if len(raw) >= _MAX_SCAN_TOKEN:
            break
        line = raw.decode("utf-8", "surrogateescape").strip(_GO_SPACE)
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) == 3:
            parts[0] = parts[0].replace("\\", "/")
        elif len(parts) == 4:
            parts[1] = parts[1].replace("\\", "/")
        joined = ":".join(parts)
        # A candidate is the text before a colon, and the last colon leaves no
        # rule and line behind it, so every colon but the last starts one.
        colons = [index for index, char in enumerate(joined) if char == ":"][:-1]
        for number, position in enumerate(colons):
            if position == 0:
                continue
            if position > MAX_CANDIDATE_LENGTH:
                # Every later prefix is longer, and none can be a file.
                break
            if (
                len(files) >= MAX_IGNORE_CANDIDATES
                or characters + position > MAX_IGNORE_CANDIDATE_CHARS
            ):
                unread += len(colons) - number
                break
            # The last component, measured before the prefix is built: more
            # characters than NAME_MAX bytes is too long in any encoding.
            first_of_last = joined.rfind("/", 0, position) + 1
            if position - first_of_last > MAX_NAME_LENGTH:
                continue
            file_part = joined[:position]
            last = file_part[first_of_last:]
            if _name_length(last) > MAX_NAME_LENGTH:
                continue
            # A name already taken is one copy and one re-scan however many
            # lines repeat it, so it costs the cap nothing. Fingerprints of one
            # file repeat its name once per finding.
            if file_part in seen:
                continue
            seen.add(file_part)
            files.append(file_part)
            characters += position
    return files, unread


def _mask_quoted_ignore_entries(log_path: Path) -> None:
    """Remove what gitleaks quotes from ``.gitleaksignore`` in its log at ``log_path``.

    gitleaks logs each line of the file it cannot parse as a fingerprint, verbatim
    (``WRN Invalid .gitleaksignore entry fingerprint=<line>``). The file is the
    scanned tree's, so the line can be anything the tree holds, a secret included.
    Each such log line is cut after the message; the rest of the log is kept.
    """
    try:
        fd = os.open(log_path, os.O_RDONLY | _NOFOLLOW | _BINARY)
    except OSError:
        return
    with os.fdopen(fd, "rb") as handle:
        text = handle.read().decode("utf-8", errors="replace")
    if INVALID_ENTRY_LOG not in text:
        return
    lines = [
        line[: line.index(INVALID_ENTRY_LOG) + len(INVALID_ENTRY_LOG)]
        + " (the entry gitleaks quoted here was removed by ASH)"
        if INVALID_ENTRY_LOG in line
        else line
        for line in text.split("\n")
    ]
    with open_for_write(log_path, encoding="utf-8", errors="replace") as handle:
        handle.write("\n".join(lines))


class GitleaksScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a gitleaks TOML config. A relative path is taken from the "
                "directory of the config file that sets it, or from the working "
                "directory for --config-overrides, not from the source directory. "
                "Its rules and [[allowlists]] apply on top of ASH suppressions. "
                f"{SET_BY_THE_OPERATOR} Unset, gitleaks uses GITLEAKS_CONFIG or "
                "GITLEAKS_CONFIG_TOML from the environment if one is set, else its "
                "default rules; a .gitleaks.toml in the scanned repository is not "
                "read. A path that does not exist fails the scan."
            ),
        ),
    ] = None
    baseline_path: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a gitleaks JSON report whose findings gitleaks ignores "
                "(gitleaks --baseline-path). A relative path is taken as for "
                f"config_file. {SET_BY_THE_OPERATOR} A path that does not exist fails "
                "the scan."
            ),
        ),
    ] = None
    honor_inline_ignores: Annotated[
        bool,
        Field(
            description=(
                "Honor gitleaks' inline `gitleaks:allow` comments. Off by default: "
                "ASH runs `gitleaks --ignore-gitleaks-allow`, so every finding "
                "reaches ASH, where suppressions are reported and counted. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with a "
                "warning."
            ),
        ),
    ] = False
    max_target_megabytes: Annotated[
        int | None,
        Field(
            description=(
                "Skip files larger than this many megabytes (gitleaks "
                "--max-target-megabytes). Unset scans every file. "
                f"{SET_BY_THE_OPERATOR} Set by such a config, it is ignored with a "
                "warning."
            ),
            ge=1,
        ),
    ] = None


class GitleaksScannerConfig(ScannerPluginConfigBase):
    name: Literal["gitleaks"] = "gitleaks"
    enabled: bool = True
    options: Annotated[
        GitleaksScannerConfigOptions,
        Field(description="Configure the gitleaks scanner"),
    ] = GitleaksScannerConfigOptions()


@ash_scanner_plugin
class GitleaksScanner(ScannerPluginBase[GitleaksScannerConfig]):
    """Secret detection over the scan target's files using gitleaks."""

    #: Not Python-only: gitleaks is a native binary, installed from its pinned
    #: release asset, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    # gitleaks' rules are compiled into the binary and it makes no network calls.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = {0, LEAKS_EXIT_CODE}
    # The strict default: no network, and no variables or paths beyond the
    # baseline. GITLEAKS_CONFIG and GITLEAKS_CONFIG_TOML are not passed into a
    # sandbox, and neither config_file nor baseline_path outside the tree is
    # mounted: grants derived from the environment or options wait for the
    # sandbox's grant gates.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    # The target, argv and .gitleaksignore content of the run whose report
    # _read_results_file reads next, for the re-scan. Set by _execute_scan.
    _pending_run: Optional[Tuple[Path, List[str], bytes]] = PrivateAttr(default=None)
    # Names the last re-scan did not reach (MAX_RESCAN_FILES, MAX_RESCAN_BYTES),
    # for the report _post_process_sarif finishes next. Reset per target in
    # _execute_scan: a source run that failed after its re-scan left the count
    # for the converted target's report.
    _rescan_skipped: int = PrivateAttr(default=0)
    # Candidate names the last read of the tree's .gitleaksignore left unread
    # (MAX_IGNORE_CANDIDATES), set by _gitleaksignore_files and taken into
    # _rescan_skipped by _add_back_gitleaksignore_drops.
    _rescan_unread: int = PrivateAttr(default=0)
    # The stderr log of a re-scan run that failed this target, for
    # _describe_scan_failure, which otherwise describes the first run's exit
    # code and log. None until a re-scan fails; reset per target.
    _rescan_failure_log: Optional[Path] = PrivateAttr(default=None)
    # Whether the tree-set honor_inline_ignores refusal was already logged.
    _ignores_refusal_logged: bool = PrivateAttr(default=False)
    # Whether the tree-set max_target_megabytes refusal was already logged.
    _size_refusal_logged: bool = PrivateAttr(default=False)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = GitleaksScannerConfig()
        self.command = "gitleaks"
        self.subcommands = ["dir"]
        self.tool_type = ScannerToolType.SECRETS
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token gitleaks would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "GitleaksScanner":
        """Install from the pinned release asset in ``utils/tool_downloads.py``."""
        self.custom_install_commands.update(pinned_tool_install_commands("gitleaks"))
        return self

    def _options(self) -> GitleaksScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, GitleaksScannerConfigOptions):
            return options
        return GitleaksScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("GitleaksScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: ASH cannot tell before gitleaks runs whether it reads any file.

        gitleaks is handed the whole target (``gitleaks dir``), walks it itself,
        and skips what its config's allowlists name, a config the operator may
        have chosen. Any file it reads can hold a secret, so ASH makes no
        selection of its own that could come up empty, and gitleaks counts no
        targets, so a run with the tool never reports that it evaluated nothing
        either. None means "cannot tell", never "nothing to scan".
        """
        return None

    def _operator_option_path(self, option: str) -> Optional[Path]:
        """``option``'s path when the operator set it, else None (with a warning).

        Through ``config_trust.operator_path``, with ``outside_tree`` off: the
        operator may keep their own config or baseline in the tree. The resolved
        path it returns is the one passed to gitleaks.

        Raises:
            ScannerError: the operator's path is not a file, or is inside the
                scanned tree and leads out of it through a symlink
                (``config_trust.LEADS_OUT_OF_THE_TREE``).
        """
        value = getattr(self._options(), option)
        if not value:
            return None
        config = self.context.config if self.context is not None else None
        chosen = operator_path(
            config,
            f"scanners.gitleaks.options.{option}",
            value,
            self._source_dir(),
            outside_tree=False,
        )
        if chosen.refusal == LEADS_OUT_OF_THE_TREE:
            raise ScannerError(
                f"scanners.gitleaks.options.{option} is {str(value)!r}, a path "
                "inside the scanned tree that resolves outside it through a "
                "symbolic link. The scanned repository decides what is at that "
                "path, so gitleaks is not given it, and gitleaks is not run."
            )
        if chosen.path is None:
            self._plugin_log(
                refusal_warning(
                    f"Ignoring scanners.gitleaks.options.{option} ({str(value)!r}): "
                    f"{chosen.refusal}. Tune findings with ASH suppressions.",
                    chosen.refusal,
                ),
                level=logging.WARNING,
            )
            return None
        if not chosen.path.is_file():
            raise ScannerError(
                f"scanners.gitleaks.options.{option} is {str(value)!r}, which is "
                f"not a file (resolved to {chosen.path.as_posix()}). Fix the path "
                f"or unset the option; gitleaks is not run without it."
            )
        return chosen.path

    def _honor_inline_ignores(self) -> bool:
        """Whether gitleaks may apply ``gitleaks:allow`` comments in the tree.

        Off unless the operator turned it on: a comment in the scanned tree drops
        a finding before ASH sees it, so it would be neither reported nor counted
        as suppressed.
        """
        if not self._options().honor_inline_ignores:
            return False
        config = self.context.config if self.context is not None else None
        if set_by_operator(
            config, "scanners.gitleaks.options.honor_inline_ignores", True
        ):
            return True
        if not self._ignores_refusal_logged:
            self._ignores_refusal_logged = True
            self._plugin_log(
                "scanners.gitleaks.options.honor_inline_ignores is true in a config "
                "inside a git checkout or the scanned directory, or from an MCP "
                "client, so it is ignored: gitleaks runs with --ignore-gitleaks-allow "
                "and gitleaks:allow comments do not apply; suppress findings with "
                f"ASH suppressions. {KEEP_A_SETTING}",
                level=logging.WARNING,
            )
        return False

    def _max_target_megabytes(self) -> Optional[int]:
        """The size above which gitleaks skips a file, when the operator set one.

        From a config inside a git checkout or the scanned directory it is ignored:
        a tree that set it could have gitleaks skip any file it holds, unreported.
        """
        value = self._options().max_target_megabytes
        if not value:
            return None
        config = self.context.config if self.context is not None else None
        if set_by_operator(
            config, "scanners.gitleaks.options.max_target_megabytes", value
        ):
            return int(value)
        if not self._size_refusal_logged:
            self._size_refusal_logged = True
            self._plugin_log(
                f"scanners.gitleaks.options.max_target_megabytes ({value}) is set "
                "in a config inside a git checkout or the scanned directory, or "
                "from an MCP client, so it is ignored and gitleaks scans files of "
                f"every size. {KEEP_A_SETTING}",
                level=logging.WARNING,
            )
        return None

    def _resolve_config_file(self) -> Optional[Path]:
        """The config to pass as ``--config``; None leaves it to the environment.

        See "The scanned repository's own gitleaks configuration is not used" in
        the module docstring.
        """
        operator_config = self._operator_option_path("config_file")
        if operator_config is not None:
            return operator_config
        set_vars = [name for name in CONFIG_ENV_VARS if os.environ.get(name)]
        if set_vars and active_scope() is not None:
            # The sandbox does not pass these variables in (see
            # sandbox_requirements), so gitleaks would not see them.
            self._plugin_log(
                f"{', '.join(set_vars)} is not passed into the scanner sandbox; "
                "gitleaks uses its default rules instead. Set "
                "scanners.gitleaks.options.config_file to choose a config.",
                level=logging.WARNING,
            )
        elif set_vars:
            # gitleaks resolves a relative GITLEAKS_CONFIG against its working
            # directory, which is the scanned source directory here, so a
            # relative value the operator set in ASH's own working directory
            # would be read from the scanned tree: the repository would supply
            # the config file. Anchor it where the operator typed it and pass
            # it as --config, which gitleaks reads before the variable. The
            # test is on the value AS GIVEN: a leading ``~`` is not absolute
            # either (a shell expands it only in some positions, and CI
            # ``env:`` blocks, ``.env`` files and ``--env-file`` never do), and
            # gitleaks does not expand it, so ``~/rules.toml`` as given would
            # name a ``~`` directory inside the scanned tree. Only a path that
            # is absolute as typed, or GITLEAKS_CONFIG_TOML (the config's text,
            # not a path), is left to gitleaks as before.
            given = self._config_env_value()
            if given and not os.path.isabs(given):
                anchored = self._anchored_config_env(given)
                ASH_LOGGER.debug(
                    "GITLEAKS_CONFIG is not an absolute path; passing it to "
                    "gitleaks resolved against the working directory ASH runs in"
                )
                return anchored
            ASH_LOGGER.debug(
                f"{', '.join(set_vars)} set; leaving gitleaks config resolution to gitleaks"
            )
            return None
        present = [n for n in TREE_CONFIG_NAMES if (self._source_dir() / n).is_file()]
        if present:
            self._plugin_log(
                f"{', '.join(present)} in the scanned tree is not read: gitleaks runs "
                "with its default rules, so its findings are reported and tuned "
                "with ASH suppressions. Set scanners.gitleaks.options.config_file "
                "with --config-overrides or a config file outside every git checkout "
                "and the scanned directory to use a gitleaks config.",
                level=logging.INFO,
            )
        # Outside the scanned tree, new for this run and removed when it ends
        # (config/tool_config_trust.empty_tool_config). It names no path, so
        # where it lives does not change what gitleaks reports.
        return empty_tool_config(
            "ash-gitleaks-default-rules.toml",
            DEFAULT_RULES_CONFIG,
            context=self.context,
        ).resolve()

    @staticmethod
    def _config_env_value() -> Optional[str]:
        """``GITLEAKS_CONFIG`` as the operator set it, or None.

        The one place this module reads the variable's value: the first run's
        anchoring (``_resolve_config_file``) and the re-scan's environment
        (``_rescan_env``) both go through it, so the builtin environment-read
        audit (tests/unit/utils/test_uv_tool_runner.py) counts one read site
        for this variable, as it did before the anchoring. The value is a path
        for the gitleaks binary, which is not installed through uv, so it never
        reaches a uv install input and is not added to ``_environment_values()``;
        the debug line that mentions it names the variable, never the value.
        """
        return os.environ.get("GITLEAKS_CONFIG")

    @staticmethod
    def _anchored_config_env(given: str) -> Path:
        """The absolute path a non-absolute ``GITLEAKS_CONFIG`` names, as ASH sees it.

        ``~`` and ``~user`` are expanded first (the operator's home, never a
        directory of that name in the scanned tree), then the result is
        resolved against the working directory ASH runs in. Never against the
        scanned source directory: that is where gitleaks would have read it,
        and the point of anchoring is that the repository does not pick the
        config.
        """
        return Path(os.path.abspath(os.path.expanduser(given)))

    def _empty_ignore_dir(self) -> Path:
        """A directory with no ``.gitleaksignore``, for ``--gitleaks-ignore-path``.

        New and empty, outside the scanned tree, removed when the run ends
        (``empty_tool_directory``).
        """
        return empty_tool_directory(
            "ash-no-gitleaksignore", context=self.context
        ).resolve()

    def _scan_path(self, target: Path) -> str:
        """The path gitleaks is given: ``.`` for the source, absolute otherwise.

        The source target as "." from the source directory (the subprocess cwd),
        so reported paths are source-relative; see the module docstring.
        """
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        """The full gitleaks argv for one target.

        Every option is one ``--flag=value`` token and the scan path follows
        ``--``, so no path or config value can be read as a flag.
        """
        args: List[str] = [
            self.command or "gitleaks",
            *self.subcommands,
            "--report-format=sarif",
            f"--report-path={results_file.as_posix()}",
            "--redact=100",
            f"--exit-code={LEAKS_EXIT_CODE}",
            "--no-banner",
            "--no-color",
            f"--gitleaks-ignore-path={self._empty_ignore_dir().as_posix()}",
        ]
        if not self._honor_inline_ignores():
            args.append("--ignore-gitleaks-allow")
        config_file = self._resolve_config_file()
        if config_file is not None:
            args.append(f"--config={config_file.as_posix()}")
        baseline = self._operator_option_path("baseline_path")
        if baseline is not None:
            args.append(f"--baseline-path={baseline.as_posix()}")
        max_mb = self._max_target_megabytes()
        if max_mb is not None:
            args.append(f"--max-target-megabytes={max_mb}")
        args.extend(["--", self._scan_path(target)])
        return args

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one gitleaks run.

        ``global_ignore_paths`` is not translated into gitleaks config: it is
        applied to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("GitleaksScanner has no results directory")
        # ScannerExecutor runs this instance over the source and then the converted
        # target, and the base class keeps the worst exit code across runs. Without
        # this, a source run that failed (1) failed a clean converted run, and one
        # that found leaks (2) made a converted run's failure (1) read as leaks.
        self.exit_code = 0
        self._rescan_skipped = 0
        self._rescan_unread = 0
        self._rescan_failure_log = None
        # Absolute: gitleaks runs with its working directory at the source (or
        # the copies) directory, and a library caller's relative output
        # directory would have it write the report there, where ASH does not
        # read it.
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "gitleaks.sarif")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's: a
        # gitleaks that fails writes no report, and the template reads whatever
        # is at this path.
        results_file.unlink(missing_ok=True)
        ignore_data = self._read_tree_ignore_file(target)
        final_args = self._build_arguments(target, results_file)
        self._pending_run = (Path(target), list(final_args), ignore_data)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Refuse the report of a run gitleaks did not finish.

        Exit 1 is a gitleaks failure (see the module docstring), and any code
        outside 0 and 2 is not one gitleaks documents. Raised before reading so
        a partial report cannot pass as a complete one.
        """
        pending, self._pending_run = self._pending_run, None
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"gitleaks exited {self.exit_code}; it exits 0 when it finds "
                f"nothing and {LEAKS_EXIT_CODE} when it finds leaks, so this run "
                "failed"
            )
        raw = super()._read_results_file(results_file)
        if raw is not None and pending is not None:
            target, final_args, ignore_data = pending
            # The file as it is now, against the read before gitleaks ran:
            # gitleaks read it by name in between, and the re-scan covers the
            # entries ASH read. The two reads bracket gitleaks' own, so a change
            # between them is caught here; nothing compared them before.
            if self._read_tree_ignore_file(target) != ignore_data:
                raise ScannerError(
                    f"The scanned tree's {IGNORE_FILE_NAME} changed while gitleaks "
                    "ran, so the files it names cannot be re-scanned as gitleaks "
                    "applied them, and the findings it hid may be missing from "
                    "this report. Run the scan again."
                )
            self._add_back_gitleaksignore_drops(
                raw, target, final_args, results_file, ignore_data
            )
            # The re-scan is part of this run: the base's _post_scan recorded
            # the end before it, and the invocation record is written after.
            self.end_time = datetime.now(timezone.utc)
        return raw

    def _read_tree_ignore_file(self, target: Path) -> bytes:
        """The content of ``<target>/.gitleaksignore``, or ``b""`` without one.

        A name that is a directory, a symlink to a directory, or a symlink that
        leads nowhere is read as no ignore file: gitleaks reads a line through
        none of them (its open of a directory reads nothing, and a dangling
        link fails its stat), so there is nothing for the re-scan to cover and
        no reason to stop.

        Raises:
            ScannerError: it is a symlink to a file, or not a regular file, or
                has a second hard link, or is larger than
                ``MAX_IGNORE_FILE_BYTES``. gitleaks opens the name itself,
                follows a symlink, blocks on a FIFO, and logs every line it
                cannot parse, so a link to a file outside the tree would put that
                file's lines into its log. gitleaks is not run. Read with
                ``open_in_scanned_tree``, which follows no link, and nothing read
                is quoted.
        """
        path = Path(target) / IGNORE_FILE_NAME
        try:
            named = os.lstat(path)
            if stat.S_ISDIR(named.st_mode):
                # gitleaks reads the name only when it is not a directory.
                return b""
            if stat.S_ISLNK(named.st_mode):
                try:
                    pointed = os.stat(path)
                except FileNotFoundError:
                    # Dangling: gitleaks' stat of the name fails, and it reads
                    # nothing.
                    return b""
                if stat.S_ISDIR(pointed.st_mode):
                    # A directory through a link: opened, read as nothing.
                    return b""
        except FileNotFoundError:
            return b""
        except OSError:
            # Not ASH's to decide: gitleaks meets the same error and fails.
            return b""
        try:
            with open_in_scanned_tree(path, target) as handle:
                data = handle.read(MAX_IGNORE_FILE_BYTES + 1)
        except TreeInputRefused as refused:
            raise ScannerError(
                f"The scanned tree's {IGNORE_FILE_NAME} is refused: "
                f"{refused.reason}. gitleaks reads that file whatever ASH passes "
                "and logs each line of it that is not a fingerprint, so gitleaks "
                "is not run. Make it a regular file in the tree, or remove it."
            ) from None
        except OSError:
            return b""
        if len(data) > MAX_IGNORE_FILE_BYTES:
            raise ScannerError(
                f"The scanned tree's {IGNORE_FILE_NAME} is larger than "
                f"{MAX_IGNORE_FILE_BYTES} bytes, so ASH cannot re-scan every file "
                "it names, and gitleaks is not run."
            )
        return data

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code, and keep gitleaks' stderr out of ``self.errors``.

        gitleaks' stderr can quote the scanned tree's ``.gitleaksignore`` (see
        ``_mask_quoted_ignore_entries``), and the scanner executor copies
        ``errors`` into the scan's results. The stream stays in the log file.
        """
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _run_subprocess(  # type: ignore[override]
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        **kwargs: Any,
    ) -> Dict[str, str]:
        """Run gitleaks, then mask what its log quotes from ``.gitleaksignore``."""
        response = super()._run_subprocess(command, results_dir=results_dir, **kwargs)
        if results_dir is not None:
            _mask_quoted_ignore_entries(
                Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
            )
        return response

    def _describe_scan_failure(
        self,
        exc: Exception,
        results_file: Optional[Path],
        tool_started: bool = True,
    ) -> str:
        """The failure and where gitleaks' log is, without quoting the log.

        The base class quotes the tool's stderr. gitleaks' can quote the scanned
        tree's ``.gitleaksignore``, and this message reaches ``ash.log``, the
        console and every results file. A failure before gitleaks started gives
        no exit code, as the base class's does, and so does a tool ASH could not
        stop: it may still be running, and the code the timeout recorded is not
        one gitleaks returned. A re-scan that failed names its own log beside
        the first run's: ``self.exit_code`` is the first run's, which was
        accepted, so that reading alone misdescribed the failure.
        """
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if not tool_started or results_file is None:
            # _execute_scan raised: gitleaks was not run, so there is no exit code.
            return f"{detail} (gitleaks was not started)"
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
        if self._rescan_failure_log is not None:
            return (
                f"{detail} (the first gitleaks run exited {self.exit_code}; the "
                f"re-scan of the files the tree's {IGNORE_FILE_NAME} names failed). "
                "gitleaks' logs are not quoted here; see "
                f"{self._rescan_failure_log.as_posix()} and {log_path.as_posix()}"
            )
        if self.scan_could_not_stop is not None:
            return (
                f"{detail} (no exit code: ASH could not stop gitleaks). gitleaks' "
                f"log is not quoted here; see {log_path.as_posix()}"
            )
        verdict = (
            "an accepted exit code for this scanner"
            if self._exit_code_accepted()
            else "not an accepted exit code; success_exit_codes="
            f"{sorted(self.success_exit_codes)}"
        )
        return (
            f"{detail} (exit code {self.exit_code}: {verdict}). gitleaks' log is "
            f"not quoted here; see {log_path.as_posix()}"
        )

    def _gitleaksignore_files(
        self, target: Path, data: Optional[bytes] = None
    ) -> List[str]:
        """The files ``<target>/.gitleaksignore`` names, relative to the target.

        Parsed as gitleaks parses it (``gitleaksignore_files``). A dir-scan
        fingerprint is ``<file>:<rule id>:<line>``; files that are not inside the
        target are left out, since gitleaks could not have matched them.

        Each path is normalized, whatever spelling the entry used (``./``, ``//``,
        ``..``, absolute), into the path the directory scan reaches the file by.
        The re-scan reports its findings in that spelling, so they compare with
        the first run's; re-scanning ``./app/x.py`` as written reported
        ``./app/x.py``, which matched none of the first run's ``app/x.py``
        results and added each of them a second time.

        ``data`` is the file's content as ``_execute_scan`` read it before the
        first run; without it the file is read now, under the same rule
        (``_read_tree_ignore_file``).

        The root is the resolved target (``_rescan_root``): the directory
        gitleaks walked, which a lexical normalization of a target spelled with
        ``..`` after a symlink is not.
        """
        if data is None:
            data = self._read_tree_ignore_file(target)
        if not data:
            return []
        target_abs = self._rescan_root(target)
        names = set()
        candidates, self._rescan_unread = gitleaksignore_candidates(data)
        for name in candidates:
            # Joining keeps an absolute entry as it is.
            lexical = Path(os.path.normpath(target_abs / name))
            if lexical == target_abs or not lexical.is_relative_to(target_abs):
                continue
            names.add(lexical.relative_to(target_abs).as_posix())
        return sorted(names)

    def _add_back_gitleaksignore_drops(
        self,
        raw: Dict[str, Any],
        target: Path,
        final_args: List[str],
        results_file: Path,
        ignore_data: Optional[bytes] = None,
    ) -> None:
        """Re-scan the files the tree's ``.gitleaksignore`` names; add what it hid.

        gitleaks reads ``<scan path>/.gitleaksignore`` whatever ASH passes, so the
        run whose report is ``raw`` may have dropped findings by fingerprint. ASH
        copies each named file into a directory of its own outside the scanned
        tree (``_rescan_copies_dir``), at the same path relative to the root, and
        runs gitleaks once over that directory with the first run's flags. Its
        reports and logs go to the results directory, the one place a sandboxed
        gitleaks may write. No ``.gitleaksignore`` is at its root, and gitleaks
        walks the copies under the same relative paths, so the directories and
        paths its allowlists skip (``.git``, by default) are skipped as they were
        in the tree, under whichever config the first run used. Results the first
        run lacks are the dropped ones, and they are appended to ``raw``. See the
        module docstring.

        What the directory scan does not read is not copied (``_copy_for_rescan``),
        and the copies, which hold the tree's secrets, are removed when the run
        ends.
        """
        relatives = self._gitleaksignore_files(target, ignore_data)
        unread, self._rescan_unread = self._rescan_unread, 0
        if unread:
            self._rescan_skipped += unread
            self._plugin_log(
                f"{unread} name(s) in the scanned tree's {IGNORE_FILE_NAME} were "
                f"not read: ASH reads at most {MAX_IGNORE_CANDIDATES} candidate "
                "names per file. The scan is reported as incomplete.",
                level=logging.WARNING,
            )
        if not relatives:
            return
        runs = raw.get("runs") or []
        if not runs:
            return
        results = runs[0].setdefault("results", None) or []
        runs[0]["results"] = results

        def key(result: Dict[str, Any]) -> Tuple[Any, ...]:
            # The whole region, not the fingerprint's line: one fingerprint hides
            # every match of its rule on the line, and each match is a finding.
            location = ((result.get("locations") or [{}])[0]).get(
                "physicalLocation", {}
            )
            region = location.get("region") or {}
            return (
                (location.get("artifactLocation") or {}).get("uri"),
                result.get("ruleId"),
                region.get("startLine"),
                region.get("startColumn"),
                region.get("endLine"),
                region.get("endColumn"),
            )

        seen = {key(result) for result in results}
        scan_path = self._scan_path(target)
        rescan_dir = results_file.parent / RESCAN_DIR_NAME
        if rescan_dir.is_symlink() or rescan_dir.is_file():
            rescan_dir.unlink()
        elif rescan_dir.is_dir():
            shutil.rmtree(rescan_dir)
        rescan_dir.mkdir(parents=True)
        copies_dir = self._rescan_copies_dir()
        added = 0
        # One deadline for every re-scan run, scan_timeout long, the copies
        # included: copying is work the tree sizes, and it ran outside the
        # deadline before.
        timeout = self._effective_scan_timeout()
        deadline = None if timeout is None else _monotonic() + timeout
        try:
            batches, copied, skipped, named = self._copy_for_rescan(
                target, relatives, copies_dir, rescan_dir, final_args, deadline
            )
            self._rescan_skipped += skipped
            if skipped:
                self._plugin_log(
                    f"{skipped} file(s) the scanned tree's {IGNORE_FILE_NAME} names "
                    f"were not re-scanned: ASH re-scans at most {MAX_RESCAN_FILES} "
                    f"files and {MAX_RESCAN_BYTES} bytes. The scan is reported as "
                    "incomplete.",
                    level=logging.WARNING,
                )
            for cwd, scan_arg, report in batches:
                remaining = None
                if deadline is not None:
                    remaining = deadline - _monotonic()
                    if remaining <= 0:
                        raise self._rescan_timeout_error(timeout)
                data = self._run_rescan(
                    final_args, cwd, scan_arg, report, rescan_dir, remaining
                )
                for run in data.get("runs") or []:
                    for result in run.get("results") or []:
                        self._respell_rescan_result(result, scan_path)
                        if key(result) not in seen:
                            seen.add(key(result))
                            results.append(result)
                            added += 1
        finally:
            # Now, not only when the run's directory goes: they hold the tree's
            # secrets.
            shutil.rmtree(copies_dir, ignore_errors=True)
        self._plugin_log(
            f"The scanned tree's {IGNORE_FILE_NAME} names {named} file(s), "
            f"{copied} of them read by the directory scan. gitleaks applies it at "
            "the scan root whatever ASH passes, so ASH re-scanned those files and "
            f"reports the {added} finding(s) it dropped. Tune findings with ASH "
            "suppressions, which are reported and counted.",
            level=logging.INFO,
        )

    @staticmethod
    def _rescan_timeout_error(timeout: Optional[float]) -> ScannerError:
        """The error for a re-scan that ran out of the shared deadline."""
        return ScannerError(
            "gitleaks timed out re-scanning the files the scanned "
            f"tree's {IGNORE_FILE_NAME} names: scan_timeout "
            f"({timeout}s) covers every re-scan run"
        )

    @staticmethod
    def _rescan_root(target: Path) -> Path:
        """The directory the re-scan reads the named files from: ``target``
        resolved, the directory gitleaks walked.

        A lexical normalization (``os.path.normpath`` of the absolute target)
        is a different directory when the target is spelled with ``..`` after
        a symlink, so the names were looked for under a root gitleaks never
        read. The resolved form also compares with the operator's baseline
        path, which ``_operator_option_path`` resolves, so a baseline inside a
        source directory reached through a link is left out of the copies as
        the docstring of ``_copy_for_rescan`` says.
        """
        return Path(os.path.realpath(target))

    def _copy_for_rescan(
        self,
        target: Path,
        relatives: List[str],
        copies_dir: Path,
        reports_dir: Path,
        final_args: List[str],
        deadline: Optional[float] = None,
    ) -> Tuple[List[Tuple[Path, str, Path]], int, int, int]:
        """Copy the named files the directory scan reads; return the runs to make.

        Returns the runs, the number of files copied, the number of files not
        checked because ``MAX_RESCAN_FILES`` files, or ``MAX_RESCAN_BYTES``
        bytes, were copied first, and the number of files the ignore file names
        (the candidates that reach a file; a name made by a colon split that
        reaches none is counted nowhere). ``deadline`` is the re-scan's shared deadline
        on ``_monotonic``'s clock; a copy that would start past it raises the
        re-scan's timeout error.

        Raises:
            ScannerError: the deadline passed, or a copy could not be written.

        Each run is ``(working directory, scan path, report path)``. The files go
        under ``copies_dir / RESCAN_TREE_DIR`` at their tree paths, scanned as
        ``.``. The root ``.gitleaksignore``, when it names itself, goes alone under
        ``copies_dir / RESCAN_SELF_DIR`` and is scanned as a file, which reads no
        ignore file: at the copy tree's root it would be read as one. Each run's
        report is in ``reports_dir``.

        Not copied, because the directory scan does not read them or ASH drops
        what it finds there:

        * a file reached through a symlink at any component, or one that is not a
          regular file (``open_in_scanned_tree``): gitleaks follows no symlink,
          and skips a FIFO or device as empty. A hard-linked file is read, as the
          walk reads it;
        * a file under one of ASH's output directories inside the target (this
          run's, and the default ``.ash/ash_output`` an earlier run left:
          ``_ash_output_dirs_inside``) that the repository did not commit
          (``_drop_results_under_output_dir``); a committed one is copied, since
          ASH keeps what it finds there (``_committed_file_test``);
        * the operator's baseline, which gitleaks does not scan;
        * an empty file, and one over ``max_target_megabytes``, which gitleaks
          skips.
        """
        target_abs = self._rescan_root(target)
        outputs_inside = self._output_dirs_inside_target(target)
        committed = self._committed_file_test()
        skipped_names = set()
        for arg in final_args:
            if arg.startswith("--baseline-path="):
                baseline = Path(os.path.realpath(arg.split("=", 1)[1]))
                if baseline.is_relative_to(target_abs):
                    skipped_names.add(baseline.relative_to(target_abs).as_posix())
        # The limit the first run was given, not the option: it may have been
        # refused (_max_target_megabytes).
        size_limit_mb = None
        for arg in final_args:
            if arg.startswith("--max-target-megabytes="):
                size_limit_mb = int(arg.split("=", 1)[1])

        tree_dir = copies_dir / RESCAN_TREE_DIR
        self_dir = copies_dir / RESCAN_SELF_DIR
        in_tree = 0
        # The names the directory lists for the ignore file: one, unless the
        # file is also linked under another name.
        itself_names: List[str] = []
        not_checked = 0
        past_the_limit = 0
        copied_bytes = 0
        listings: Dict[Path, Set[str]] = {}
        spellings_seen: Set[str] = set()

        def unreached(rest: List[str]) -> int:
            """How many of the names in ``rest`` reach a file not yet seen.

            A candidate that names no file (``app/x.py:my`` from the colon
            splits of ``app/x.py:my:rule:4``) is not a file the re-scan missed,
            so it is not counted.
            """
            reached: Set[str] = set()
            for name in rest:
                spelled = self._on_disk_spelling(target_abs, name, listings)
                if (
                    spelled is not None
                    and spelled not in spellings_seen
                    and spelled not in skipped_names
                ):
                    reached.add(spelled)
            return len(reached)

        for index, relative in enumerate(relatives):
            if deadline is not None and _monotonic() >= deadline:
                raise self._rescan_timeout_error(self._effective_scan_timeout())
            # Only a name the directories list exactly (_on_disk_spelling): the
            # rejoined ignore line is matched exactly against the name the
            # directory scan reports, so an entry in another case hid nothing.
            # A name that reaches no file is skipped here, as the open below
            # skipped it.
            spelled = self._on_disk_spelling(target_abs, relative, listings)
            if spelled is None or spelled in spellings_seen:
                continue
            spellings_seen.add(spelled)
            relative = spelled
            if relative in skipped_names:
                continue
            if any(
                PurePosixPath(relative).is_relative_to(output.as_posix())
                for output in outputs_inside
            ) and not committed(Path(os.path.normpath(target_abs / relative))):
                continue
            # The ignore file itself goes alone, under the name the directory
            # lists, and is decided by identity (_is_the_ignore_file): a
            # repository's `.GITLEAKSIGNORE` on a case-insensitive filesystem
            # is the file gitleaks reads, and at the copy tree's root it would
            # be read as the ignore file again.
            is_ignore_file = self._is_the_ignore_file(target_abs, relative)
            destination = (self_dir if is_ignore_file else tree_dir) / relative
            # The limit is tested for a name that reaches a file the re-scan
            # would copy, after the lookup: a made-up name sorted after the
            # last real file is not a file left behind, and a tree that names
            # exactly MAX_RESCAN_FILES real files was re-scanned in full.
            if in_tree + len(itself_names) >= MAX_RESCAN_FILES:
                past_the_limit = unreached(relatives[index + 1 :])
                not_checked += 1 + past_the_limit
                break
            try:
                handle = open_in_scanned_tree(
                    target_abs / relative, target_abs, allow_hardlinks=True
                )
            except TreeInputRefused:
                continue
            except (OSError, ValueError):
                # Missing, unreadable, or a name no file can have: the directory
                # scan read nothing there either.
                continue
            with handle:
                size = os.fstat(handle.fileno()).st_size
                # gitleaks' own test: a file is skipped when its size in whole
                # megabytes (size / 1,000,000, integer division) is over the
                # limit, so a file a few bytes past limit * 1,000,000 is still
                # scanned, and a byte-exact test here left such a file out of
                # the re-scan, its hidden findings with it.
                if size == 0 or (
                    size_limit_mb is not None and size // 1_000_000 > size_limit_mb
                ):
                    continue
                if copied_bytes + size > MAX_RESCAN_BYTES:
                    # This file does not fit what is left of the budget: it is
                    # reported as not evaluated, and the names after it are
                    # still tried, since a smaller one may fit. Stopping here
                    # left every later file un-scanned behind one large file
                    # that sorted early.
                    not_checked += 1
                    continue
                copied_bytes += size
                try:
                    _write_private_copy(handle, destination)
                except OSError as exc:
                    # ASH's own failure, not the tree's: skipping the file would
                    # leave what the ignore file hides in it unreported.
                    raise ScannerError(
                        "ASH could not copy a file the scanned tree's "
                        f"{IGNORE_FILE_NAME} names for its re-scan "
                        f"({exc.strerror or type(exc).__name__}); without the "
                        "re-scan the findings the file hides would go unreported"
                    ) from None
            if is_ignore_file:
                itself_names.append(relative)
            else:
                in_tree += 1

        # The copy filesystem's own matching is the last test: a name the tree's
        # filesystem keeps apart from the ignore file can be the same file on
        # the copies', and gitleaks would read the copy at the tree's root as
        # the ignore file. Without the re-scan what the file hides would not be
        # reported, so the scan fails instead.
        if in_tree and (tree_dir / IGNORE_FILE_NAME).exists():
            raise ScannerError(
                f"A file the scanned tree's {IGNORE_FILE_NAME} names would be read "
                f"as {IGNORE_FILE_NAME} when ASH copies it for the re-scan, because "
                "the filesystem the copies are made on matches names differently "
                "from the scanned tree's; without the re-scan the findings the "
                "file hides would not be reported"
            )

        batches = []
        if in_tree:
            batches.append((tree_dir, ".", reports_dir / "tree.sarif"))
        for number, name in enumerate(itself_names):
            report = "self.sarif" if number == 0 else f"self-{number}.sarif"
            batches.append((self_dir, name, reports_dir / report))
        # The files the ignore file names: the ones the directories list, whether
        # or not they were copied (spellings_seen), and those after the file the
        # file limit stopped at.
        named = len(spellings_seen) + past_the_limit
        return batches, in_tree + len(itself_names), not_checked, named

    @staticmethod
    def _on_disk_spelling(
        root: Path,
        relative: str,
        listings: Dict[Path, Set[str]],
    ) -> Optional[str]:
        """``relative`` when every directory under ``root`` lists it as spelled, or None.

        gitleaks walks the directory and reports each file by the name the
        directory lists. The rejoined ``.gitleaksignore`` line is matched
        EXACTLY against ``<file>:<rule>:<line>`` with that name, so an entry
        spelled in another letter case hid no finding, even where the
        filesystem opens the listed file under that spelling (macOS and Windows
        by default). Mapping such an entry to the listed name bought a copy and
        a re-scan whose results were all de-duplicated, and the spelling it
        copied under matched none of the first run's results and added every
        finding a second time, or made two copies of one path, which failed the
        scan. A name some directory does not list exactly is None.

        ``listings`` caches each directory's entries across the entries of one
        ignore file, read once per directory and held as a set of its names, so
        the lookup is constant in the directory's size: the ignore file can hold
        up to ``MAX_IGNORE_FILE_BYTES`` of entries, with the ones that name no
        file or repeat one not counting toward ``MAX_RESCAN_FILES``.
        """
        current = root
        for part in PurePosixPath(relative).parts:
            names = listings.get(current)
            if names is None:
                try:
                    with os.scandir(current) as entries:
                        names = {entry.name for entry in entries}
                except OSError:
                    return None
                listings[current] = names
            if part not in names:
                return None
            current = current / part
        return relative

    @staticmethod
    def _is_the_ignore_file(root: Path, relative: str) -> bool:
        """Whether ``relative``, a name the directory lists, is the file gitleaks
        reads as ``<root>/.gitleaksignore``.

        Decided by identity and not by spelling: on a case-insensitive
        filesystem (macOS and Windows by default) a repository that commits the
        file as ``.GITLEAKSIGNORE`` has it read as the ignore file, and the
        directory lists that spelling. Copied to the copy tree's root, which is
        on a filesystem of its own that reads names the same way, it would be
        read as the ignore file again and hide the same fingerprints in the
        re-scan.
        """
        if relative == IGNORE_FILE_NAME:
            return True
        if "/" in relative:
            return False
        try:
            return os.path.samefile(root / relative, root / IGNORE_FILE_NAME)
        except OSError:
            return False

    def _rescan_copies_dir(self) -> Path:
        """A new, empty directory for the re-scan's copies, outside the scanned tree.

        Made with mode 0700 in the scanner run's own directory
        (``empty_tool_directory``), so it is removed with the run even when the
        re-scan never gets to remove it, and a sandboxed gitleaks may read it and
        not write it. It used to be under the results directory, which is inside
        the scanned tree with the default output directory, so the copies of the
        tree's files sat in the tree being scanned.

        Raises:
            ScannerError: it could not be made. Without the re-scan the findings
                the ignore file hides would go unreported.
        """
        try:
            return empty_tool_directory(RESCAN_DIR_NAME, context=self.context)
        except OSError as exc:
            raise ScannerError(
                "ASH could not make the directory for the re-scan of the files the "
                f"scanned tree's {IGNORE_FILE_NAME} names "
                f"({exc.strerror or type(exc).__name__}); without the re-scan the "
                "findings those files hide would go unreported"
            ) from None

    def _run_rescan(
        self,
        final_args: List[str],
        cwd: Path,
        scan_arg: str,
        report: Path,
        rescan_dir: Path,
        timeout: Optional[float],
    ) -> Dict[str, Any]:
        """Run gitleaks with the first run's flags over ``scan_arg`` from ``cwd``.

        ``timeout`` is what is left of the shared deadline. A run that fails is
        described by how it failed: a timeout (recorded against the whole
        ``scan_timeout``, the limit the operator set, not the share this run
        got), a start that failed, an exit code gitleaks does not use for a
        finished run, or no report. Its log is named for ``_describe_scan_failure``.

        An empty report, or one with no run, fails too, as the first run's does
        (``_read_results_file``, ``scan``): gitleaks' writer always emits a
        document with a run, so either is a write that did not finish, and
        reading it as no dropped findings would silently keep what the ignore
        file hid out of the report.

        Raises:
            ScannerError: the run did not finish, or its report cannot be graded.
        """
        args = [
            f"--report-path={report.as_posix()}"
            if arg.startswith("--report-path=")
            else arg
            for arg in final_args[:-1]
        ] + [scan_arg]
        exit_code = self.exit_code
        response = self._run_subprocess(
            command=args,
            results_dir=rescan_dir,
            cwd=cwd,
            env=self._rescan_env(final_args),
            timeout=timeout,
        )
        self.exit_code = exit_code
        code = response.get("returncode", 1) if isinstance(response, dict) else 1
        why: Optional[str] = None
        if not isinstance(response, dict):
            why = "no response from the run"
        elif response.get("timed_out"):
            # The base's _run_subprocess recorded this run's share of the
            # deadline as the limit; the limit is scan_timeout.
            self._record_timeout(response, self._effective_scan_timeout())
            why = (
                f"it timed out: scan_timeout ({self._effective_scan_timeout()}s) "
                "covers every re-scan run"
            )
        elif response.get("spawn_failed"):
            why = "gitleaks could not be started"
        elif code not in self.success_exit_codes:
            why = f"exit {code}"
        elif not report.is_file():
            why = "it wrote no report"
        if why is not None:
            self._rescan_failure_log = (
                rescan_dir / f"{self.__class__.__name__}.stderr.log"
            )
            raise ScannerError(
                "gitleaks failed re-scanning the files the scanned tree's "
                f"{IGNORE_FILE_NAME} names ({why}); without that run the "
                "findings the file hides would go unreported. gitleaks' log is "
                f"not quoted here; see {self._rescan_failure_log.as_posix()}"
            )
        text = report.read_text(encoding="utf-8")
        if not text.strip():
            raise ScannerError(
                "gitleaks wrote an empty report re-scanning the files the scanned "
                f"tree's {IGNORE_FILE_NAME} names, so there is nothing to grade; "
                "without that run the findings the file hides would go unreported"
            )
        data = json.loads(text)
        if not isinstance(data, dict) or not data.get("runs"):
            raise ScannerError(
                "gitleaks' report of the re-scan of the files the scanned tree's "
                f"{IGNORE_FILE_NAME} names holds no SARIF run, so there is nothing "
                "to grade; without that run the findings the file hides would go "
                "unreported"
            )
        return data

    def _rescan_env(self, final_args: List[str]) -> Optional[Dict[str, str]]:
        """The re-scan's environment: a non-absolute ``GITLEAKS_CONFIG`` made absolute.

        Only when no ``--config`` is passed, which is the only case gitleaks reads
        the variable in. ``_resolve_config_file`` now anchors a non-absolute
        ``GITLEAKS_CONFIG`` to the directory ASH runs in and passes it as
        ``--config``, so this branch is not reached for it; it stays for a run
        that reaches gitleaks with the variable alone, where the re-scan from the
        copies must still read the same file as the first run. The anchor is
        the same one (``_anchored_config_env``): the directory ASH runs in, with
        ``~`` expanded, never the scanned source directory, which an earlier
        shape used here and which would have let the scanned repository supply
        the re-scan's config.
        """
        if any(arg.startswith("--config=") for arg in final_args):
            return None
        value = self._config_env_value()
        if not value or os.path.isabs(value):
            return None
        return {
            **snapshot_environ(),
            "GITLEAKS_CONFIG": self._anchored_config_env(value).as_posix(),
        }

    @staticmethod
    def _respell_rescan_result(result: Dict[str, Any], scan_path: str) -> None:
        """Give a re-scan result the URI the directory scan reports its file under.

        The copies are scanned from their own root, so gitleaks reports each by
        its path relative to the target: the source scan's spelling already. The
        converted target is scanned by its absolute path, so its URIs are too.
        """
        if scan_path == ".":
            return
        for location in result.get("locations") or []:
            artifact = (location.get("physicalLocation") or {}).get(
                "artifactLocation"
            ) or {}
            uri = artifact.get("uri")
            if uri:
                # Cleaned, as gitleaks' filepath.Join cleans each path it walks.
                artifact["uri"] = posixpath.normpath(f"{scan_path}/{uri}")

    def _committed_file_test(self) -> Callable[[Path], bool]:
        """A test, of a path, for a file the repository committed under ASH's output.

        The output directory is a path inside the scanned tree, and a repository
        can commit files to it. Those files are the tree's own, so a finding in
        one is about the tree and not a copy of something ASH wrote. They are the
        files ``scan_output_dirs.committed_output_files`` reads: the files of the
        scan set that are under ASH's output directories, which in a git checkout
        are the ones git tracks. The executor's drop and the suppression step read
        the same set, and keep the results located in those files.

        The set is read when the test is first asked, so a run with nothing under
        the output directory reads nothing, and a path is compared resolved, as
        the set is. Outside a checkout, and where git cannot say what is tracked,
        the set is empty: every file under the output directory is then ASH's.

        A path that cannot be resolved, such as a symlink loop or a name holding a
        null byte, which an entry in the tree's ``.gitleaksignore`` can spell, is
        not committed. The file stays treated as ASH's own, as it was before.
        """
        committed: Optional[Set[Path]] = None

        def is_committed(path: Path) -> bool:
            nonlocal committed
            if committed is None:
                committed = committed_output_files(self.context)
            try:
                return path.resolve() in committed
            except (OSError, RuntimeError, ValueError):
                return False

        return is_committed

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove the results located under ASH's output directory inside ``target``.

        See "Paths" in the module docstring. Nothing is removed when the output
        directory is not inside ``target`` (``_output_dir_inside``): when it is
        outside, and for the converted target, which lives under it. A location
        is joined to the target and normalized lexically, without resolving
        symlinks, as ``_output_dir_inside`` compares the two directories.

        A result in a file the repository committed under the output directory is
        kept (``_committed_file_test``): only what ASH wrote there is dropped.

        Every ASH output directory inside the target counts
        (``_output_dirs_inside_target``): this run's, and the default
        ``.ash/ash_output`` an earlier run left in the tree, as every other
        directory-walking scanner skips both.

        A URI's backslashes are read as separators only where the platform
        writes them (Windows, where gitleaks joins paths with ``\\``). On POSIX
        a backslash is a character of a file's name, and reading it as a
        separator let a file named like ``out\\x`` read as a path under the
        output directory, and its findings were dropped.
        """
        if self.context is None:
            return
        outputs_inside = self._output_dirs_inside_target(target)
        if not outputs_inside:
            return
        target_abs = Path(target).absolute()
        output_roots = [Path(os.path.normpath(target_abs / o)) for o in outputs_inside]
        committed = self._committed_file_test()

        def under_output_dir(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if not uri:
                    continue
                if os.sep == "\\":
                    uri = uri.replace("\\", "/")
                path = Path(os.path.normpath(target_abs / uri))
                if any(path.is_relative_to(root) for root in output_roots) and (
                    not committed(path)
                ):
                    return True
            return False

        dropped = 0
        for run in sarif_report.runs or []:
            if not run.results:
                continue
            kept = [result for result in run.results if not under_output_dir(result)]
            dropped += len(run.results) - len(kept)
            run.results = kept
        if dropped:
            self._plugin_log(
                f"Dropped {dropped} finding(s) under ASH's output directory: copies "
                "of the files ASH converted, which the converted target's run "
                "reports, or files ASH wrote.",
                level=logging.DEBUG,
            )

    def _output_dirs_inside_target(self, target: Path) -> List[Path]:
        """ASH's output directories inside ``target``, relative to it.

        This run's output directory when it sits inside the target
        (``_output_dir_inside``), whole, and the directories
        ``_ash_output_dirs_inside`` names: the default ``.ash/ash_output`` an
        earlier run left in the tree, and for a directory holding committed
        files ASH's own directories in it. The first keeps the drop of every
        uncommitted file under this run's output, the files at its root
        included, which the second lists only in part. Empty for the converted
        target, which lives under the output directory.
        """
        found: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            found.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in found:
                found.append(relative)
        return found

    def _report_rescan_skipped(self, sarif_report: SarifReport) -> None:
        """Record the names the re-scan did not reach as a run that is incomplete.

        An error-level ``toolExecutionNotifications`` entry on the invocation,
        which ``run_ash_scan.unevaluated_rules`` reads: the scan exits 1 as
        incomplete rather than reading as clean, since a finding the tree's
        ``.gitleaksignore`` hides in those files is not reported. A count, not the
        names, which are the tree's text.
        """
        skipped, self._rescan_skipped = self._rescan_skipped, 0
        if not skipped or not sarif_report.runs:
            return
        notification = Notification(
            level=Level.error,
            message=Message(
                root=Message1(
                    text=(
                        f"gitleaks: {skipped} file(s) the scanned tree's "
                        f"{IGNORE_FILE_NAME} names were not re-scanned, past "
                        f"ASH's limits of {MAX_RESCAN_FILES} files, "
                        f"{MAX_RESCAN_BYTES} bytes and {MAX_IGNORE_CANDIDATES} "
                        "names read, so a finding that file hides in them is "
                        "not reported."
                    )
                )
            ),
        )
        run = sarif_report.runs[0]
        if not run.invocations:
            run.invocations = [Invocation(executionSuccessful=True)]
        invocation = run.invocations[0]
        invocation.toolExecutionNotifications = [
            *(invocation.toolExecutionNotifications or []),
            notification,
        ]

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, rate every result, drop empty fingerprints, keep
        snippets redacted, and report the files the re-scan did not reach."""
        self._drop_results_under_output_dir(sarif_report, target)
        self._report_rescan_skipped(sarif_report)
        for result in sarif_report.get_all_results():
            # See "Severity" in the module docstring.
            result.level = Level.error
            result.kind = Kind.fail

            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("secret", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", "CRITICAL")  # noqa: B010

            for location in result.locations or []:
                physical = location.physicalLocation
                region = physical.root.region if physical else None
                snippet = region.snippet if region else None
                if snippet is not None and snippet.text not in (None, REDACTED):
                    snippet.text = REDACTED

            # gitleaks fills commitSha/author/email/date/commitMessage with empty
            # strings in dir mode. An empty fingerprint is identical across every
            # result, so it is dropped rather than passed on.
            fingerprints = result.partialFingerprints
            if fingerprints:
                kept = {k: v for k, v in fingerprints.items() if v not in ("", None)}
                result.partialFingerprints = kept or None

        run = sarif_report.runs[0] if sarif_report.runs else None
        if run is not None and run.tool and run.tool.driver:
            # gitleaks 8.30.1 writes semanticVersion "v8.0.0" whatever its real
            # version; leave it out rather than report a wrong one.
            run.tool.driver.semanticVersion = None
        return sarif_report
