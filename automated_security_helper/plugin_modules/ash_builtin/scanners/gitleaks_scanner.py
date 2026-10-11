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
* ``--gitleaks-ignore-path=<empty directory ASH writes>``: by default gitleaks
  reads ``.gitleaksignore`` from its working directory, the source directory.

The scanned repository's own gitleaks configuration is not used
---------------------------------------------------------------
A ``.gitleaks.toml`` can replace gitleaks' rules or allowlist any path, and a
``.gitleaksignore`` or a baseline report drops findings by fingerprint. gitleaks
applies all of them before ASH sees a result, so what they hide is neither
reported nor counted as suppressed. Findings are tuned with ASH suppressions,
which are both, so the scanned tree does not configure gitleaks:

* The config is the operator's ``options.config_file`` (set by
  ``--config-overrides`` or a config file outside the scanned tree,
  ``utils/config_trust.py``), else ``GITLEAKS_CONFIG`` or ``GITLEAKS_CONFIG_TOML``
  from the operator's environment (outside the scanner sandbox, which does not
  pass them in), else a config ASH writes that extends gitleaks' default rules and
  adds nothing. It is always passed as ``--config`` except in the environment
  case, so gitleaks never falls through to ``<target>/.gitleaks.toml``. A
  ``config_file`` or ``baseline_path`` set by a config in the scanned tree is
  ignored with a warning, and a ``.gitleaks.toml`` or ``.ash/.gitleaks.toml`` in
  the tree with a note. An operator's file that does not exist fails the scan
  rather than falling back to the default rules.
* ``.gitleaksignore``: gitleaks reads ``<scan path>/.gitleaksignore`` whatever
  ``--gitleaks-ignore-path`` says, and has no flag to turn that off (measured on
  8.30.1). When the scan root has one, ASH copies the files it names into a
  directory of its own, at their paths relative to the root, runs gitleaks once
  more over that directory (no ``.gitleaksignore`` is there), and adds back every
  finding the first run dropped. gitleaks walks the copies under the same
  relative paths, so the directories its allowlists skip (``.git``, by default)
  are skipped there too, and ASH copies nothing the walk would not read: no file
  reached through a symlink, nothing that is not a regular file, nothing under
  ASH's output directory, not the operator's baseline. A failed re-run fails the
  scan rather than reporting the first run alone, and the copies are removed when
  it ends. It copies at most ``MAX_RESCAN_FILES`` files, and its runs share one
  ``scan_timeout``; names past the limit are reported as not evaluated, which
  makes the scan incomplete.
* Inline ``gitleaks:allow`` comments drop a finding the same way, so ASH passes
  ``--ignore-gitleaks-allow``. ``options.honor_inline_ignores: true`` turns them
  back on; it is honored only when the operator set it, and from a config in the
  scanned tree it is ignored with a warning.
* A ``.gitleaksignore`` that is a symlink, not a regular file, or hard-linked
  stops the scanner before gitleaks runs (``_read_tree_ignore_file``): gitleaks
  opens the name, follows the link, and logs each line it cannot parse. ASH reads
  the file once, without following a link, and parses what it read. gitleaks'
  log is never quoted in an error, and the lines in it that quote the file are
  cut (``_mask_quoted_ignore_entries``).

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
detect-secrets, zizmor and actionlint leave it out of the files they scan.
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
from pathlib import Path, PurePosixPath
from typing import (
    Annotated,
    Any,
    BinaryIO,
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
from automated_security_helper.utils.config_trust import operator_path, set_by_operator
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import active_scope
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)

#: The text gitleaks writes in place of a secret under ``--redact``.
REDACTED = "REDACTED"

#: Exit code gitleaks is told to use when it finds leaks. See the module docstring.
LEAKS_EXIT_CODE = 2

#: gitleaks config names a repository commits. ASH does not read them from the
#: scanned tree; they are named only in the note logged when one is present.
TREE_CONFIG_NAMES = (".gitleaks.toml", ".ash/.gitleaks.toml")

#: Environment variables gitleaks reads a config from. When either is set, outside
#: the scanner sandbox, ASH passes no ``--config`` and gitleaks resolves it.
CONFIG_ENV_VARS = ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")

#: The ignore file gitleaks always reads at the root of its scan path.
IGNORE_FILE_NAME = ".gitleaksignore"

#: Under the re-scan directory: the copies of the files ``.gitleaksignore``
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

#: Most bytes of the tree's ``.gitleaksignore`` ASH reads. A larger file stops
#: the scan: its entries could not all be re-scanned.
MAX_IGNORE_FILE_BYTES = 32 * 1024 * 1024

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

    ``O_EXCL`` and ``O_NOFOLLOW``: the file must not exist, so nothing left in the
    re-scan directory can redirect the write. The copy holds the tree's secrets
    until the re-scan removes it.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY,
        0o600,
    )
    with os.fdopen(fd, "wb") as out:
        shutil.copyfileobj(source, out)


def gitleaksignore_files(data: bytes) -> List[str]:
    """The file part of each fingerprint in ``data``, as gitleaks 8.30.1 reads it.

    ``Detector.AddGitleaksIgnore`` (``detect/detect.go`` at v8.30.1) reads the
    file with a ``bufio.Scanner`` (``ScanLines``: lines end at ``\n`` alone, one
    trailing ``\r`` dropped, reading stops at a line of 64 KiB or more), trims each
    line with ``strings.TrimSpace``, skips empty lines and lines starting with
    ``#``, splits on ``:`` and replaces ``\\`` with ``/`` in the file part: the
    first of three parts, or the second of four (``commit:file:rule:line``). The
    rejoined line is matched exactly against each finding's
    ``<file>:<rule>:<line>`` (``AddFinding``), so the file it can hide is
    everything before the last two ``:``. A line with fewer than three parts can
    hide nothing.

    Bytes are decoded with ``surrogateescape``, so a name that is not UTF-8 maps
    back to the same bytes on disk.
    """
    files = []
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
        file_part = ":".join(parts).rsplit(":", 2)
        if len(file_part) == 3 and file_part[0]:
            files.append(file_part[0])
    return files


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
                "Path to a gitleaks TOML config, relative to the source directory. "
                "Its rules and [[allowlists]] apply on top of ASH suppressions. "
                "Honored only when set by --config-overrides or a config file "
                "outside the scanned tree. Unset, gitleaks uses GITLEAKS_CONFIG or "
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
                "Path to a gitleaks JSON report, relative to the source directory, "
                "whose findings gitleaks ignores (gitleaks --baseline-path). Honored "
                "only when set by --config-overrides or a config file outside the "
                "scanned tree. A path that does not exist fails the scan."
            ),
        ),
    ] = None
    honor_inline_ignores: Annotated[
        bool,
        Field(
            description=(
                "Honor gitleaks' inline `gitleaks:allow` comments. Off by default: "
                "gitleaks runs with `--ignore-gitleaks-allow`, so every finding "
                "reaches ASH, where suppressions are reported and counted. Honored "
                "only when set by --config-overrides or a config file outside the "
                "scanned tree; from a config in the scanned tree it is ignored "
                "with a warning."
            ),
        ),
    ] = False
    max_target_megabytes: Annotated[
        int | None,
        Field(
            description=(
                "Skip files larger than this many megabytes (gitleaks "
                "--max-target-megabytes). Unset scans every file. Honored only "
                "when set by --config-overrides or a config file outside the "
                "scanned tree; from a config in the scanned tree it is ignored "
                "with a warning."
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
    # Names the last re-scan did not reach (MAX_RESCAN_FILES), for the report
    # _post_process_sarif finishes next.
    _rescan_skipped: int = PrivateAttr(default=0)
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

    def _operator_option_path(self, option: str) -> Optional[Path]:
        """``option``'s path when the operator set it, else None (with a warning).

        Through ``config_trust.operator_path``, with ``outside_tree`` off: the
        operator may keep their own config or baseline in the tree. The resolved
        path it returns is the one passed to gitleaks.

        Raises:
            ScannerError: the operator's path is not a file.
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
        if chosen.path is None:
            self._plugin_log(
                f"Ignoring scanners.gitleaks.options.{option} ({str(value)!r}): "
                f"{chosen.refusal}. Tune findings with ASH suppressions.",
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
                "in the scanned tree or from an MCP client, so it is ignored: "
                "gitleaks runs with --ignore-gitleaks-allow and gitleaks:allow "
                "comments do not apply. Set it with --config-overrides or a config "
                "file outside the scanned tree, or suppress findings with ASH "
                "suppressions.",
                level=logging.WARNING,
            )
        return False

    def _max_target_megabytes(self) -> Optional[int]:
        """The size above which gitleaks skips a file, when the operator set one.

        From a config in the scanned tree it is ignored: a tree that set it could
        have gitleaks skip any file it holds, unreported.
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
                "in a config in the scanned tree or from an MCP client, so it is "
                "ignored and gitleaks scans files of every size. Set it with "
                "--config-overrides or a config file outside the scanned tree.",
                level=logging.WARNING,
            )
        return None

    def _resolve_config_file(self, results_dir: Path) -> Optional[Path]:
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
                "with --config-overrides or a config file outside the scanned tree "
                "to use a gitleaks config.",
                level=logging.INFO,
            )
        default_rules = results_dir / "ash-gitleaks-default-rules.toml"
        with open_for_write(default_rules) as handle:
            handle.write(DEFAULT_RULES_CONFIG)
        return default_rules.resolve()

    def _empty_ignore_dir(self, results_dir: Path) -> Path:
        """A directory with no ``.gitleaksignore``, for ``--gitleaks-ignore-path``."""
        empty = results_dir / "ash-no-gitleaksignore"
        if empty.is_symlink() or empty.is_file():
            empty.unlink()
        elif empty.is_dir():
            for child in empty.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        empty.mkdir(parents=True, exist_ok=True)
        return empty.resolve()

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
        results_dir = results_file.parent
        args: List[str] = [
            self.command or "gitleaks",
            *self.subcommands,
            "--report-format=sarif",
            f"--report-path={results_file.as_posix()}",
            "--redact=100",
            f"--exit-code={LEAKS_EXIT_CODE}",
            "--no-banner",
            "--no-color",
            f"--gitleaks-ignore-path={self._empty_ignore_dir(results_dir).as_posix()}",
        ]
        if not self._honor_inline_ignores():
            args.append("--ignore-gitleaks-allow")
        config_file = self._resolve_config_file(results_dir)
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
        results_file = self.results_dir.joinpath(target_type, "gitleaks.sarif")
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
            self._add_back_gitleaksignore_drops(
                raw, target, final_args, results_file, ignore_data
            )
        return raw

    def _read_tree_ignore_file(self, target: Path) -> bytes:
        """The content of ``<target>/.gitleaksignore``, or ``b""`` without one.

        Raises:
            ScannerError: it is a symlink, or not a regular file, or has a second
                hard link, or is larger than ``MAX_IGNORE_FILE_BYTES``. gitleaks
                opens the name itself, follows a symlink, blocks on a FIFO, and
                logs every line it cannot parse, so a link to a file outside the
                tree (``/proc/self/environ``) would put that file into its log.
                gitleaks is not run. Read with ``open_in_scanned_tree``, which
                follows no link, and nothing read is quoted.
        """
        path = Path(target) / IGNORE_FILE_NAME
        try:
            if stat.S_ISDIR(os.lstat(path).st_mode):
                # gitleaks reads the name only when it is not a directory.
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
        self, exc: Exception, results_file: Optional[Path]
    ) -> str:
        """The failure and where gitleaks' log is, without quoting the log.

        The base class quotes the tool's stderr. gitleaks' can quote the scanned
        tree's ``.gitleaksignore``, and this message reaches ``ash.log``, the
        console and every results file.
        """
        detail = f"{self.__class__.__name__} scan failed: {exc}"
        if results_file is None:
            # _execute_scan raised: gitleaks was not run, so there is no exit code.
            return detail
        verdict = (
            "an accepted exit code for this scanner"
            if self._exit_code_accepted()
            else "not an accepted exit code; success_exit_codes="
            f"{sorted(self.success_exit_codes)}"
        )
        log_path = Path(results_file).parent / f"{self.__class__.__name__}.stderr.log"
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
        """
        if data is None:
            data = self._read_tree_ignore_file(target)
        if not data:
            return []
        target_abs = Path(os.path.normpath(Path(target).absolute()))
        names = set()
        for name in gitleaksignore_files(data):
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
        copies each named file into a directory of its own, at the same path
        relative to the root, and runs gitleaks once over that directory with the
        first run's flags. No ``.gitleaksignore`` is at its root, and gitleaks
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
        rescan_dir = results_file.parent / "gitleaksignore-rescan"
        if rescan_dir.is_symlink() or rescan_dir.is_file():
            rescan_dir.unlink()
        elif rescan_dir.is_dir():
            shutil.rmtree(rescan_dir)
        rescan_dir.mkdir(parents=True)
        added = 0
        # One deadline for every re-scan run, scan_timeout long.
        timeout = self._effective_scan_timeout()
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            batches, copied, skipped = self._copy_for_rescan(
                target, relatives, rescan_dir, final_args
            )
            self._rescan_skipped = skipped
            if skipped:
                self._plugin_log(
                    f"{skipped} file(s) the scanned tree's {IGNORE_FILE_NAME} names "
                    f"were not re-scanned: ASH re-scans at most {MAX_RESCAN_FILES}. "
                    "The scan is reported as incomplete.",
                    level=logging.WARNING,
                )
            for cwd, scan_arg, report in batches:
                remaining = None
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ScannerError(
                            "gitleaks timed out re-scanning the files the scanned "
                            f"tree's {IGNORE_FILE_NAME} names: scan_timeout "
                            f"({timeout}s) covers every re-scan run"
                        )
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
            for copies in (RESCAN_TREE_DIR, RESCAN_SELF_DIR):
                shutil.rmtree(rescan_dir / copies, ignore_errors=True)
        self._plugin_log(
            f"The scanned tree's {IGNORE_FILE_NAME} names {len(relatives)} file(s), "
            f"{copied} of them read by the directory scan. gitleaks applies it at "
            "the scan root whatever ASH passes, so ASH re-scanned those files and "
            f"reports the {added} finding(s) it dropped. Tune findings with ASH "
            "suppressions, which are reported and counted.",
            level=logging.INFO,
        )

    def _copy_for_rescan(
        self,
        target: Path,
        relatives: List[str],
        rescan_dir: Path,
        final_args: List[str],
    ) -> Tuple[List[Tuple[Path, str, Path]], int, int]:
        """Copy the named files the directory scan reads; return the runs to make.

        Returns the runs, the number of files copied, and the number of names
        not checked because ``MAX_RESCAN_FILES`` files were copied first.

        Each run is ``(working directory, scan path, report path)``. The files go
        under ``RESCAN_TREE_DIR`` at their tree paths, scanned as ``.``. The root
        ``.gitleaksignore``, when it names itself, goes alone under
        ``RESCAN_SELF_DIR`` and is scanned as a file, which reads no ignore file:
        at the copy tree's root it would be read as one.

        Not copied, because the directory scan does not read them or ASH drops
        what it finds there:

        * a file reached through a symlink at any component, or one that is not a
          regular file (``open_in_scanned_tree``): gitleaks follows no symlink,
          and skips a FIFO or device as empty. A hard-linked file is read, as the
          walk reads it;
        * a file under ASH's output directory (``_drop_results_under_output_dir``);
        * the operator's baseline, which gitleaks does not scan;
        * an empty file, and one over ``max_target_megabytes``, which gitleaks
          skips.
        """
        target_abs = Path(os.path.normpath(Path(target).absolute()))
        output_inside = self._output_dir_inside(target)
        skipped_names = set()
        for arg in final_args:
            if arg.startswith("--baseline-path="):
                baseline = Path(os.path.normpath(Path(arg.split("=", 1)[1]).absolute()))
                if baseline.is_relative_to(target_abs):
                    skipped_names.add(baseline.relative_to(target_abs).as_posix())
        # The limit the first run was given, not the option: it may have been
        # refused (_max_target_megabytes).
        size_limit = None
        for arg in final_args:
            if arg.startswith("--max-target-megabytes="):
                size_limit = int(arg.split("=", 1)[1]) * 1_000_000

        tree_dir = rescan_dir / RESCAN_TREE_DIR
        self_dir = rescan_dir / RESCAN_SELF_DIR
        in_tree = 0
        itself = False
        not_checked = 0
        for index, relative in enumerate(relatives):
            if in_tree + int(itself) >= MAX_RESCAN_FILES:
                not_checked = len(relatives) - index
                break
            if relative in skipped_names:
                continue
            if output_inside is not None and PurePosixPath(relative).is_relative_to(
                output_inside.as_posix()
            ):
                continue
            destination = (self_dir if relative == IGNORE_FILE_NAME else tree_dir) / (
                relative
            )
            try:
                with open_in_scanned_tree(
                    target_abs / relative, target_abs, allow_hardlinks=True
                ) as handle:
                    size = os.fstat(handle.fileno()).st_size
                    if size == 0 or (size_limit is not None and size > size_limit):
                        continue
                    _write_private_copy(handle, destination)
            except TreeInputRefused:
                continue
            except (OSError, ValueError):
                # Missing, unreadable, or a name no file can have.
                continue
            if relative == IGNORE_FILE_NAME:
                itself = True
            else:
                in_tree += 1

        batches = []
        if in_tree:
            batches.append((tree_dir, ".", rescan_dir / "tree.sarif"))
        if itself:
            batches.append((self_dir, IGNORE_FILE_NAME, rescan_dir / "self.sarif"))
        return batches, in_tree + int(itself), not_checked

    def _run_rescan(
        self,
        final_args: List[str],
        cwd: Path,
        scan_arg: str,
        report: Path,
        rescan_dir: Path,
        timeout: Optional[float],
    ) -> Dict[str, Any]:
        """Run gitleaks with the first run's flags over ``scan_arg`` from ``cwd``."""
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
        if (
            not isinstance(response, dict)
            or response.get("timed_out")
            or response.get("spawn_failed")
            or code not in self.success_exit_codes
            or not report.is_file()
        ):
            raise ScannerError(
                "gitleaks failed re-scanning the files the scanned tree's "
                f"{IGNORE_FILE_NAME} names (exit {code}); without that run the "
                "findings the file hides would go unreported"
            )
        return json.loads(report.read_text(encoding="utf-8") or "{}")

    def _rescan_env(self, final_args: List[str]) -> Optional[Dict[str, str]]:
        """The re-scan's environment: a relative ``GITLEAKS_CONFIG`` made absolute.

        The first run resolves it from the source directory, its working
        directory; the re-scan runs from the copies. Only when no ``--config`` is
        passed, which is the only case gitleaks reads the variable in.
        """
        if any(arg.startswith("--config=") for arg in final_args):
            return None
        value = os.environ.get("GITLEAKS_CONFIG")
        if not value or Path(value).is_absolute():
            return None
        return {
            **snapshot_environ(),
            "GITLEAKS_CONFIG": (self._source_dir() / value).absolute().as_posix(),
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

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove the results located under ASH's output directory inside ``target``.

        See "Paths" in the module docstring. Nothing is removed when the output
        directory is not inside ``target`` (``_output_dir_inside``): when it is
        outside, and for the converted target, which lives under it. A location
        is joined to the target and normalized lexically, without resolving
        symlinks, as ``_output_dir_inside`` compares the two directories.
        """
        if self.context is None or self._output_dir_inside(target) is None:
            return
        output_abs = Path(os.path.normpath(Path(self.context.output_dir).absolute()))
        target_abs = Path(target).absolute()

        def under_output_dir(result: Any) -> bool:
            for location in result.locations or []:
                physical = location.physicalLocation
                artifact = physical.root.artifactLocation if physical else None
                uri = artifact.uri if artifact else None
                if not uri:
                    continue
                path = Path(os.path.normpath(target_abs / uri.replace("\\", "/")))
                if path.is_relative_to(output_abs):
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
                        f"ASH's limit of {MAX_RESCAN_FILES}, so a finding that file "
                        "hides in them is not reported."
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
