# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered config's scanner exclusions are reported, not applied.

Why this exists
---------------
A config an MCP client delivered may set its own suppressions and ignore paths,
as a repository's config may on the CLI, and each one it supplies is marked
``client_supplied``: a finding it hides is kept in the results, suppressed and
marked, so the results show what the client's config hid
(``config/client_config_policy.py``). Several scanners also take exclusions in
their own options, and those keep files away from the scanner altogether, so
before this nothing in the results showed what a client's config had left out.

For each option in ``SCANNER_EXCLUSION_OPTIONS``, an entry the operator did not
supply is removed from a delivered config before the scanner runs, and is
recorded on the config (``AshConfig._client_scanner_exclusions``). After the
scan, ``utils/sarif_utils.apply_suppressions_to_sarif`` suppresses and marks
each finding of that scanner the entry would have kept out, the same way it
handles a client-supplied ignore path. Syft writes an SBOM rather than
findings, so a syft entry instead marks each SBOM component it would have
dropped (``mark_sbom_components``).

An entry is the operator's when the option's default has it, the trusted config
has it, or a file of the chain that no client delivered has it, in its
``scanners`` section or in a ``patch`` operation it carries. Those stay in
the option and apply as before; a client entry that repeats an operator's path
is replaced in the option by the operator's own entry, so the operator's reason
and expiration govern it, never the client's copy. A client entry that has
expired is neither applied nor recorded: the scanner would not have applied it,
so there is nothing to mark. Only the section ``get_plugin_config`` reads for
the scanner records exclusions; an entry a delivered file wrote under another
spelling the scanner never reads (``bandit-scanner`` beside ``bandit``) is
moved out, with a warning, and recorded as nothing, since it excluded nothing.

opengrep, semgrep and trivy-repo are among the scanners whose whole section a
client may not set (the always-denied floor in ``ash_config.ALWAYS_DENIED_PATHS``).
For them too the denied-fields check of a delivered file sees the section as the
move leaves it: the floor's whole-section entry does not refuse an option the
move empties of client values (``moved_exclusion_pointers``), and every other
value the file sets in the section is still refused. An operator's own
``denied_paths`` entry for the option still refuses it. The runtime-override
gate on ``select_profile``'s ``patch_ops`` and ``override_yaml`` and the
workspace tools' ``config_overrides`` leaves these options to resolution the
same way (``runtime_patch._writes_a_moved_exclusion``). A client's list may
leave out some of the operator's entries; the scanner then scans those files
too.

Options that exclude by something other than a path (``exclude_rule``, a
detect-secrets baseline, or a whole category such as checkov's
``skip_frameworks`` or ferret-scan's ``checks``) have no file to scan instead,
so they are in the default ``denied_paths`` and a delivered config that changes
one is refused. ``test_every_option_that_may_filter_findings_is_classified``
keeps every scanner option of that kind in one list or the other.

Matching
--------
Each entry is matched the way its scanner reads it, as closely as can be done
on a finding's path after the fact:

* bandit ``excluded_paths``: the ``--exclude`` globs bandit is given for the
  entry (``bandit_scanner.bandit_excluded_path_globs``, anchored at the scan
  root, which is read off the finding's absolute and relative paths), matched
  as bandit 1.9.4 matches them: ``fnmatch`` against the file's absolute path, or
  a plain substring of it. One builder serves the argument and this matcher, so
  the matcher cannot drift from what bandit skipped. (It matched the retired
  unanchored ``**/<path>/**`` against the absolute path before: an entry naming
  a directory above the scan root suppressed every bandit finding, a file entry
  such as ``app.py`` suppressed nothing, and ``.`` or an empty entry became
  ``**/**`` and suppressed everything, while bandit had excluded none of it.)
* checkov ``skip_path``: as checkov's own filter reads it, a regular
  expression found in, or a substring of, the absolute path of the file or of a
  directory above it (``checkov_skips``). The expression is the client's and
  would run in ASH's own process, so it runs in a child process under the
  scanner's ``scan_timeout``, carried on the entry when it is moved, and is
  killed at that limit (``evaluated_within``); checkov itself would have been
  killed at it.
* opengrep and semgrep ``exclude``, ferret-scan ``exclude_patterns``, syft
  ``exclude``: a glob read as those tools read it (gitignore syntax for the
  grep family, doublestar globs for syft): ``*``, ``?`` and ``[...]`` match
  within one path component and never cross ``/``, ``**`` matches any run of
  components, a pattern with no ``/`` matches a file or directory of that name
  at any depth, and a ``/`` inside the pattern, a leading ``/`` or a leading
  ``./`` anchors it at the scan root, unless it starts with ``**/``. A match on
  a directory excludes everything under it (``glob_excludes``). ferret-scan is
  given its ``exclude_patterns`` joined with commas, so an entry holding a
  comma was several patterns to it and is matched as each of them.
* trivy and trivy-repo ``ignore_file``: the file lists finding IDs. Each
  unexpired ID becomes an entry that matches a finding of that scanner with
  that rule ID, compared exactly as trivy compares them (an ``AVD-`` prefix on
  either side aside, since trivy matches a misconfiguration by its ID and by
  its AVD ID); in a ``.trivyignore.yaml`` an entry's ``paths`` limit it to the
  files those globs name, matched whole from the scan root as trivy matches
  them (``trivy_path_matches``), and an entry with ``purls`` is not applied at
  all, since the packages it is limited to are not matched here. The file is
  read only when it is a regular file inside the tree being scanned, opened
  without following a link (``utils/scanned_tree.open_in_scanned_tree``). A
  file elsewhere, or a link to one, is not read, since its contents would then
  reach the results, and its entries are not applied; the scan's warnings say
  so without quoting it. A relative value a delivered file gives is taken from
  the scanned tree's root, not from the file's own directory as the option
  documents for an operator's file: the delivered file sits outside the tree,
  and only a file inside the tree is read.
* A finding whose path the SARIF step could not make relative to the source
  directory arrives absolute. The scanner read its exclusion over the scanned
  tree, so such a finding names no file of it and no exclusion hides it: it is
  reported, never suppressed on a guess.

Known limitations
-----------------
* A tool can also leave files or findings out through a config or ignore file
  of its own. Those config files are the operator's: checkov's and
  ferret-scan's config files, detect-secrets' plugin files and trivy-repo's
  secret file are honored only from outside the scanned tree
  (``config/path_trust.py``), bandit's, grype's and syft's come only from the
  trusted config (``config/tool_config_trust.py``), those of actionlint,
  cfn-guard, cfn-lint, gitleaks, trivy and zizmor only from the operator
  (``utils/config_trust.py``), and the default ``denied_paths`` refuse a
  delivered config that names one. An ignore file a
  tool reads from the tree on its own (such as a ``.semgrepignore``) is not
  re-applied here.
* The glob matching above is an approximation of each tool's own rules. A
  finding it misses is reported unsuppressed, which can fail a scan the
  client's exclusion would have passed; it is never hidden. One known
  difference: semgrep and opengrep anchor a leading ``/``, and a pattern with
  a ``/`` inside, at their project root, the top level of the repository the
  scanned tree is in, while the matching here anchors at the scan root. The
  two are one directory when the scanned tree is the repository's root.
* A regular expression is bounded by running it in a child process that is
  killed at the deadline (``evaluated_within``): one worker process per
  suppression pass, started at its first bounded search and reused (a fork of
  ASH's own process on Linux, a fresh interpreter elsewhere), and one more
  after each kill. A pass spends one ``scan_timeout`` over all of its
  searches, not one per finding, and does not search again an entry that ran
  out (``EvaluationBudget``). The scan it was part of fails at the deadline.

Rejected alternatives
---------------------
* Converting each entry into a ``global_settings.suppressions`` entry. A
  suppression path is matched with ASH's glob rules and applies to every
  scanner's findings, which neither checkov's regular expressions nor a
  one-scanner exclusion fit.
* Denying these options outright. The user's decision was that a delivered
  config's exclusions are honored and marked, as its suppressions are.
"""

from __future__ import annotations

import fnmatch
import functools
import multiprocessing
import os
import posixpath
import re
import sys
import time
import weakref
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    TypeVar,
)

from pydantic import BaseModel, ConfigDict
from typing_extensions import Self

from automated_security_helper.core.exceptions import ScannerError

ExclusionKind = Literal["bandit", "checkov", "glob", "trivy-ignore-file"]

T = TypeVar("T")

#: A trivy ignore file larger than this is not read.
_MAX_IGNORE_FILE_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ScannerExclusionOption:
    """One scanner option that keeps files or findings away from its scanner."""

    #: The scanner's config name, which its results carry as ``scanner_name``.
    scanner: str
    #: The option's field name under ``scanners.<scanner>.options``.
    option: str
    kind: ExclusionKind
    #: The option's default entries (patterns), which are ASH's own.
    default: Tuple[str, ...] = ()

    @property
    def key(self) -> str:
        return f"scanners.{self.scanner}.options.{self.option}"


#: The options whose client-supplied entries are re-applied as marked
#: suppressions. ``test_the_table_defaults_are_the_scanners_defaults`` checks
#: ``default`` against each scanner's own option default.
SCANNER_EXCLUSION_OPTIONS: Tuple[ScannerExclusionOption, ...] = (
    ScannerExclusionOption("bandit", "excluded_paths", "bandit"),
    ScannerExclusionOption("checkov", "skip_path", "checkov"),
    ScannerExclusionOption(
        "opengrep", "exclude", "glob", ("*-converted.py", "*_report_result.txt")
    ),
    ScannerExclusionOption(
        "semgrep", "exclude", "glob", ("*-converted.py", "*_report_result.txt")
    ),
    ScannerExclusionOption("syft", "exclude", "glob"),
    ScannerExclusionOption("ferret-scan", "exclude_patterns", "glob"),
    ScannerExclusionOption("trivy-repo", "ignore_file", "trivy-ignore-file"),
    ScannerExclusionOption("trivy", "ignore_file", "trivy-ignore-file"),
)


class ClientScannerExclusion(BaseModel):
    """An exclusion a delivered config gave one scanner, applied after the scan."""

    model_config = ConfigDict(frozen=True)

    scanner: str
    option: str
    kind: ExclusionKind
    #: The path pattern, regular expression, or (for trivy) finding ID.
    pattern: str
    reason: str
    #: For a trivy ID from a ``.trivyignore.yaml``: the paths it is limited to.
    paths: Tuple[str, ...] = ()
    #: The scanner's ``scan_timeout`` when the entry was moved out of its
    #: options: the bound a regular expression of this entry runs under when
    #: ASH evaluates it in its own process (``evaluated_within``). None is
    #: ``scan_timeout: null``, which leaves the scanner unbounded but gives the
    #: client's pattern the scanners' default (``_unbounded_ceiling``).
    scan_timeout: Optional[float] = None

    @property
    def key(self) -> str:
        return f"scanners.{self.scanner}.options.{self.option}"

    def applies_to(self, scanner_name: Optional[str]) -> bool:
        """Whether a finding reported by ``scanner_name`` is this exclusion's scanner's."""
        if not scanner_name:
            return False
        return _reduced(scanner_name) == _reduced(self.scanner)

    def hides(
        self,
        *,
        relative: str,
        absolute: str,
        rule_id: Optional[str],
        budget: Optional["EvaluationBudget"] = None,
    ) -> bool:
        """Whether the scanner would have left out a finding at this location.

        ``relative`` is the finding's path from the scan root. The SARIF step
        leaves a path it could not make relative to the source directory
        absolute, and such a finding names no file of the scanned tree the
        scanner read its exclusion over, so no path pattern hides it (an ID
        alone, with no ``paths`` limit, still does). Before, an absolute
        ``relative`` was matched as a run of directories, so an unanchored
        glob or a checkov substring took the directories above the scan root.

        ``budget`` is the suppression pass's ``EvaluationBudget``: a checkov
        regular expression of this entry is searched within what is left of
        the pass's one ``scan_timeout`` (``checkov_skips``); with none, each
        call is bounded on its own.

        Raises:
            ScannerError: a checkov regular expression of this entry ran past
                ``scan_timeout`` (``checkov_skips``).
        """
        if self.kind == "bandit":
            return bandit_would_skip(self.pattern, relative=relative, absolute=absolute)
        # The path is placed once, and every matcher reads the placed form: a
        # matcher handed the spelling (``x/../vendor/a.py``) would take its
        # ``x`` and ``..`` for directories of the file.
        placed = _placed_in_tree(relative)
        if self.kind == "checkov":
            return placed is not None and checkov_skips(
                self.pattern,
                absolute,
                placed,
                timeout=self.scan_timeout,
                budget=budget,
            )
        if self.kind == "glob":
            return placed is not None and any(
                glob_excludes(pattern, placed) for pattern in self._globs()
            )
        if not rule_id or not _same_trivy_id(rule_id, self.pattern):
            return False
        if not self.paths:
            return True
        return placed is not None and any(
            trivy_path_matches(path, placed) for path in self.paths
        )

    def _globs(self) -> List[str]:
        """The globs the scanner read ``pattern`` as.

        ferret-scan is given ``exclude_patterns`` as one ``--exclude`` value
        joined with commas, so an entry holding a comma was several patterns
        to it. Matched whole before, such an entry excluded nothing here.
        """
        if self.scanner == "ferret-scan":
            return self.pattern.split(",")
        return [self.pattern]

    def justification(self) -> str:
        what = (
            f"ignore file entry '{self.pattern}'"
            if self.kind == "trivy-ignore-file"
            else f"entry '{self.pattern}'"
        )
        return (
            f"(ASH, client-supplied config) Suppressing finding excluded by "
            f"{self.key} {what} with reason: {self.reason}"
        )


@functools.lru_cache(maxsize=4096)
def _reduced(name: str) -> str:
    """``reduced_plugin_name``, remembered per name.

    ``applies_to`` runs once per finding location per exclusion. A delivered
    trivy ignore file of up to 1 MiB yields tens of thousands of entries, and
    each reduction ran two regular expressions, so the suppression step of a
    large result set ran for hours. Plugin names are a small set.
    """
    from automated_security_helper.config.ash_config import reduced_plugin_name

    return reduced_plugin_name(name)


def _has_a_drive(path: str) -> bool:
    """Whether ``path`` starts with a Windows drive letter (``C:/``)."""
    return len(path) >= 2 and path[1] == ":" and path[0].isalpha()


def _names_no_root(relative: str) -> bool:
    """Whether a finding's ``relative`` path names no file of the scanned tree.

    The SARIF step leaves a path it could not make relative to the source
    directory as it was, absolute or climbing out of the tree, and such a
    finding names no file the scanner read its exclusion over, so no path
    pattern hides it. One reading for every entry kind: a leading ``/`` (how
    the SARIF step spells a POSIX root), a drive letter (``C:/``), or a first
    component of ``..``. ``Path.is_absolute`` was the reading for the glob,
    checkov and trivy kinds: it is true for a leading ``/`` on POSIX alone and
    for a drive on Windows alone, and false for ``..`` everywhere, so each
    platform matched the other's spelling, and a ``../`` path, as a run of
    directories above the scan root.

    The path is collapsed first (``posixpath.normpath``), so one that climbs out
    partway, ``x/../../vendor/a.py``, reads as the ``../vendor/a.py`` it is; only
    a leading ``..`` was looked for before, and an unanchored entry hid such a
    finding as a file inside the tree.
    """
    return _placed_in_tree(relative) is None


def _placed_in_tree(relative: str) -> Optional[str]:
    """The path ``relative`` names from the scan root, collapsed; None when it names no file of the tree.

    Every leading ``./`` is taken off before the root and drive checks, so
    ``.//etc/x`` and ``./C:/x`` read as the absolute paths they are, not as
    paths inside the tree. What is left is collapsed (``posixpath.normpath``),
    so ``x/../vendor/a.py`` is ``vendor/a.py``. The matchers are handed this
    form and never the spelling: ``glob_excludes`` kept the ``..`` as a
    directory of the file, and an unanchored entry ``x`` hid a finding the
    scanner had reported at ``vendor/a.py``, which this module never does.
    """
    below = _slashed(relative)
    while below.startswith("./"):
        below = below[2:]
    if not below or below.startswith("/") or _has_a_drive(below):
        return None
    below = posixpath.normpath(below)
    if below == "." or below.split("/", 1)[0] == "..":
        return None
    return below


def bandit_would_skip(pattern: str, *, relative: str, absolute: str) -> bool:
    """Whether bandit, given ``excluded_paths`` entry ``pattern``, skips the file at ``absolute``.

    The entry's ``--exclude`` globs come from the builder the scanner uses
    (``bandit_scanner.bandit_excluded_path_globs``), anchored at the scan root,
    and are matched as bandit 1.9.4 matches them (``manager._is_file_included``):
    ``fnmatch`` against the walked path, or a plain substring of it. The root is
    the part of ``absolute`` above ``relative``. A finding whose absolute path is
    not ``<root>/<relative>`` (an absolute URI the SARIF step could not make
    relative to the source directory) names no root, so nothing is hidden: that
    finding is reported, never suppressed on a guess.

    A backslash in either path is read as a separator only where the platform
    reads it so (``_slashed``). On POSIX it is a character of the file's name:
    rewritten to ``/`` here before, the file ``vendor\\x.py`` was matched as
    ``vendor/x.py``, so an entry naming the latter hid a finding bandit had
    reported, since bandit matched its globs against the name as it is.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        bandit_excluded_path_globs,
    )

    below = _placed_in_tree(relative)
    if below is None:
        # An absolute "relative" path is the SARIF step's sign that it could
        # not place the finding under the source directory: no root is known.
        return False
    path = _slashed(absolute)
    if not path.endswith("/" + below):
        return False
    root = path[: -(len(below) + 1)]
    if not root:
        return False
    return any(
        fnmatch.fnmatchcase(path, entry) or entry in path
        for entry in bandit_excluded_path_globs(root, pattern)
    )


def evaluated_within(
    timeout: Optional[float], source: str, function: Callable[..., T], *args: Any
) -> T:
    """``function(*args)``, finished within ``timeout`` seconds, or a ScannerError naming ``source``.

    For a regular expression the scanned repository or a delivered config wrote
    and ASH evaluates in its own process (a detect-secrets baseline's
    ``should_exclude_file`` patterns, checkov's ``skip_path`` entries): the tool
    would have run it under the scanner's ``scan_timeout``, so here it gets the
    same bound. The call runs in a child process, which is killed at the
    deadline; its result, or the exception it raised, comes back as if the call
    had run inline. With ``timeout`` None (the scanner left unbounded) it runs
    in the child too, under the scanners' default scan_timeout
    (``_unbounded_ceiling``) and not without a deadline: the pattern is the
    client's. Inline, the matcher would hold this process's interpreter lock
    for the whole search and freeze every thread.

    A thread cannot bound it. Python's matcher holds the interpreter lock for
    the whole of a search and returns to no one until it is done, so a thread
    joined with a timeout learned of the overrun only once the search had
    finished on its own, which is when the bound no longer mattered; the first
    cut did that, and a search that backtracked for an hour held the scan for
    an hour. A process of its own can be killed. ``function`` is a module-level
    function and ``args`` are plain values (the pattern's text, the candidate
    paths): they cross to the child, which on platforms without ``fork`` is a
    fresh interpreter that imports this module by name (``_process_context``).
    """
    budget = EvaluationBudget()
    try:
        return budget.evaluate(timeout, source, source, function, *args)
    finally:
        budget.close()


class EvaluationTimedOut(ScannerError):
    """A bounded evaluation ran to its deadline and was stopped there."""


class EvaluationBudget:
    """One time balance for every bounded search of a suppression pass, with a memory.

    A pass over a SARIF run asks each client-supplied exclusion about each
    finding (``matching_exclusion`` -> ``hides`` -> ``checkov_skips``). Bounded
    per call, one entry could spend a whole ``scan_timeout`` on every finding,
    so a run of a thousand findings waited a thousand timeouts before the pass
    failed, where checkov itself would have been killed once. The budget keeps
    one balance per distinct ``scan_timeout``, and every evaluation under that
    timeout is charged the time its search took in the worker, no more: the
    rest of the pass (the other matching, the symbol reads, the git reads, the
    pipe, a spawned interpreter's start) is not regular-expression time, and
    charged to a wall-clock deadline that opened at the first search it failed
    every later match of a pass that simply ran longer than the timeout. An
    entry whose search ran to the end of the balance is remembered by its
    ``key``, and a later question about it fails at once with the same answer
    instead of starting another search; so does any evaluation once the
    balance is spent.

    The searches run in ONE child process the budget starts at its first
    bounded evaluation and reuses for the rest (``_EvaluationWorker``): a
    process per search cost a fork per finding on Linux and a fresh interpreter
    per finding where the start method is ``spawn`` (Windows, macOS), where a
    pass of many findings spent its ``scan_timeout`` on interpreter starts
    alone. A search killed at the deadline takes the worker with it, and the
    next evaluation starts a new one. ``close()`` ends the worker; the pass
    calls it when it is done, and a budget that is dropped unclosed closes its
    worker when it is collected (``weakref.finalize``), so no child outlives
    the pass by more than that. The pass creates one budget and hands it down
    (``utils/sarif_utils.apply_suppressions_to_sarif``); ``evaluated_within``
    is one evaluation under a budget of its own, closed right after, which is
    how a caller with no pass (the detect-secrets scanner's one filter) uses
    the bound.
    """

    def __init__(self) -> None:
        #: Seconds of search time spent so far, per ``scan_timeout``.
        self._spent: Dict[float, float] = {}
        self._timed_out: Dict[str, str] = {}
        self._worker = _EvaluationWorker()
        self._finalizer = weakref.finalize(self, self._worker.close)

    def close(self, graceful: bool = True) -> None:
        """End the worker process, if one is running. The budget stays usable.

        ``graceful`` is handed to the worker (``_EvaluationWorker.close``).
        """
        self._worker.close(graceful)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def worker_pid(self) -> Optional[int]:
        """The pid of the running worker, or None when none is running."""
        return self._worker.pid

    def remaining(self, timeout: float) -> float:
        """Seconds of search time left under ``timeout``: the timeout less what the worker spent."""
        return timeout - self._spent.get(timeout, 0.0)

    @property
    def timed_out(self) -> Tuple[str, ...]:
        """The keys whose evaluation ran to the deadline, in that order."""
        return tuple(self._timed_out)

    def evaluate(
        self,
        timeout: Optional[float],
        source: str,
        key: str,
        function: Callable[..., T],
        *args: Any,
    ) -> T:
        """``function(*args)`` within what is left of ``timeout``, or a ScannerError.

        ``timeout`` None (the scanner left unbounded) is the scanners' default
        scan_timeout here (``_unbounded_ceiling``), never no deadline: the
        expression is the client's, and a delivered ``scan_timeout: null``
        paired with a backtracking one parked the pass on a wait with no end and
        its worker at full CPU. The search runs in the worker, never inline (a
        client's expression would hold this process's interpreter lock for the
        whole search). ``key`` names the entry for the memory (the pattern as
        the option holds it); ``source`` names it for the error.
        """
        if timeout is None:
            timeout = _unbounded_ceiling()
        if key in self._timed_out:
            raise ScannerError(
                f"A regular expression from {source} already ran past {timeout} "
                "seconds, the scanner's scan_timeout, earlier in this pass. It is "
                "not searched again, and the scan fails."
            )
        remaining = self.remaining(timeout)
        if remaining <= 0:
            self._timed_out[key] = source
            raise ScannerError(
                f"The scanner's scan_timeout of {timeout} seconds was spent on "
                f"earlier regular expressions of this pass before one from {source} "
                "could be searched. The scan fails rather than run past it."
            )
        ran_out = False
        try:
            return self._worker.evaluate(remaining, timeout, source, function, args)
        except EvaluationTimedOut:
            self._timed_out[key] = source
            ran_out = True
            raise
        finally:
            # Charged once, here. A search that ran to the end of what was left
            # leaves nothing, whatever the clock read when the kill landed; the
            # balance was set to the timeout in the handler and then charged the
            # killed search's seconds again, which left it below zero.
            spent = self._spent.get(timeout, 0.0) + self._worker.last_search_seconds
            self._spent[timeout] = timeout if ran_out else min(spent, timeout)


class _EvaluationWorker:
    """One child process that runs a budget's bounded searches, one at a time.

    Started at the first evaluation and reused for the next ones; each
    evaluation sends ``(function, args)`` over the pipe and waits up to ``wait``
    seconds for ``(True, result)`` or ``(False, error)`` back. A search still
    running at the deadline cannot be interrupted inside the child (the matcher
    returns to no one until it is done), so the whole child is killed
    (``EvaluationTimedOut``) and the next evaluation starts a new one. A child
    that ends without answering (killed from outside, or an answer that could
    not be sent) fails the evaluation too, named as such, so the scan never
    guesses at a match it did not see.

    The request crosses the pipe by pickle on every platform (a process per
    search handed it to a forked child in memory), so ``function`` and ``args``
    must be picklable: a module-level function with plain arguments is, and the
    three handed in here are. An argument that cannot be pickled raises in the
    caller before anything is sent, with the worker idle and in step.

    Under the ``fork`` start method the child begins with a copy of every open
    descriptor, the parent's end of its own pipe included; the child closes that
    copy first thing, so a parent that dies without ``close()`` (SIGKILL,
    ``os._exit``) leaves the worker reading end-of-file on its next ``recv`` and
    exiting, instead of blocking on a pipe whose other end it holds itself.
    """

    def __init__(self) -> None:
        self._process: Any = None
        self._connection: Any = None
        #: How long the last ``evaluate`` waited on the child for its answer,
        #: from the request sent to the answer (or the kill): the search itself,
        #: without the start of a child that was not running yet.
        self.last_search_seconds = 0.0

    @property
    def pid(self) -> Optional[int]:
        if self._process is None or not self._process.is_alive():
            return None
        return self._process.pid

    def evaluate(
        self,
        wait: Optional[float],
        timeout: Optional[float],
        source: str,
        function: Callable[..., T],
        args: Tuple[Any, ...],
    ) -> T:
        """``function(*args)`` in the worker, killed when ``wait`` seconds pass.

        ``wait`` is what is left of ``timeout``, the scanner's ``scan_timeout``,
        which the error names. Both None waits for the answer with no deadline,
        for a scanner left unbounded: the search still runs in the child.
        """
        self.last_search_seconds = 0.0
        connection = self._started()
        began = time.monotonic()
        try:
            connection.send((function, args))
            # The search is timed from here: ``_started`` has waited for a
            # worker that is running (its package import is behind it), and the
            # request is pickled and written. Neither is regular-expression
            # time, and a first search charged them failed a small
            # scan_timeout on a pattern that finishes at once.
            began = time.monotonic()
            if not connection.poll(wait):
                raise EvaluationTimedOut(
                    f"A regular expression from {source} did not finish matching "
                    f"within {timeout} seconds, the scanner's scan_timeout. Its "
                    "evaluation was stopped, and the scan fails rather than wait on "
                    "it."
                )
            answered, payload = connection.recv()
        except EvaluationTimedOut:
            self.close(graceful=False)
            raise
        except (EOFError, OSError):
            self.close(graceful=False)
            raise ScannerError(
                f"The evaluation of a regular expression from {source} ended without "
                "an answer, so the scan fails rather than guess at one."
            ) from None
        finally:
            self.last_search_seconds = time.monotonic() - began
        if answered:
            return payload
        raise payload

    def close(self, graceful: bool = True) -> None:
        """End the worker, if one is running.

        ``graceful`` asks an idle worker to leave on its own and waits half a
        second for it; a worker caught mid-search (the deadline case) is killed
        outright, since nothing inside it will read the request.
        """
        process, connection = self._process, self._connection
        self._process = self._connection = None
        if connection is not None:
            if graceful and process is not None and process.is_alive():
                try:
                    connection.send(None)
                except (OSError, ValueError):
                    pass
            connection.close()
        if process is not None:
            if graceful:
                process.join(0.5)
            if process.is_alive():
                process.kill()
            process.join()

    def _started(self) -> Any:
        if self._process is not None and self._process.is_alive():
            return self._connection
        self.close()
        context = _process_context()
        parent_end, child_end = context.Pipe(duplex=True)
        # A forked child inherits the parent's end too and must close its copy
        # (see _serve_evaluations). A spawned child inherits nothing, and handing
        # it the parent's end would duplicate that end into it instead.
        if context.get_start_method() == "fork":
            arguments: Tuple[Any, ...] = (child_end, parent_end)
        else:
            arguments = (child_end,)
        process = context.Process(
            target=_serve_evaluations,
            args=arguments,
            name="ash-pattern-evaluation",
            daemon=True,
        )
        process.start()
        child_end.close()
        self._process, self._connection = process, parent_end
        # The child reports once it is running: where it is a fresh interpreter
        # (``spawn``) it first imports this package, which takes seconds on a
        # loaded host, and the first search of the worker was charged those
        # seconds. The wait for it has a bound of its own, and a child that
        # never reports fails the start, not a search.
        try:
            ready = (
                parent_end.poll(_WORKER_START_BOUND)
                and parent_end.recv() == _WORKER_READY
            )
        except (EOFError, OSError):
            ready = False
        if not ready:
            self.close(graceful=False)
            raise ScannerError(
                "The process that evaluates a delivered regular expression did not "
                f"start within {_WORKER_START_BOUND:g} seconds, so the scan fails "
                "rather than guess at a match it did not see."
            )
        return parent_end


#: What the worker sends first, once it is running and its package is imported.
_WORKER_READY = "ash-pattern-evaluation-ready"

#: Seconds a started worker has to send ``_WORKER_READY``. Generous: a fresh
#: interpreter importing this package on a busy host is the slow case.
_WORKER_START_BOUND = 120.0


def _serve_evaluations(connection: Any, inherited_parent_end: Any = None) -> None:
    """In the worker: report ready, then answer each ``(function, args)`` job until None or the pipe ends.

    The first thing sent is ``_WORKER_READY``, which ``_EvaluationWorker._started``
    waits for, so the time a fresh interpreter takes to import this package is
    not the first search's. ``inherited_parent_end`` is the parent's end of this pipe as a forked child
    inherited it; it is closed first, so the pipe's only open parent end is the
    parent's own and its closing (a ``close()``, or the parent's death) reaches
    this loop as end-of-file. A result or an error that cannot be pickled is
    replaced by a ScannerError that names its type, so the parent always reads
    one answer per job.
    """
    if inherited_parent_end is not None:
        inherited_parent_end.close()
    try:
        try:
            connection.send(_WORKER_READY)
        except (OSError, ValueError):
            return
        while True:
            try:
                job = connection.recv()
            except EOFError:
                return
            if job is None:
                return
            function, args = job
            try:
                answer: Tuple[bool, Any] = (True, function(*args))
            except BaseException as error:  # re-raised in the caller's process
                answer = (False, error)
            try:
                connection.send(answer)
            except Exception:
                what = "result" if answer[0] else type(answer[1]).__name__
                connection.send(
                    (
                        False,
                        ScannerError(
                            f"The evaluation's {what} could not be handed back from "
                            "the process it ran in."
                        ),
                    )
                )
    finally:
        connection.close()


def _process_context() -> Any:
    """The multiprocessing context the evaluation worker is started with.

    ``fork`` on Linux: the child starts with this module and the compiled
    pattern already in memory, in milliseconds (the detect-secrets scanner
    forces the same method for its own worker). Elsewhere the platform's
    default (``spawn`` on Windows and macOS), which starts a fresh interpreter
    and imports the evaluated function by its module and name, which is why
    every function handed to ``evaluated_within`` is defined at module level;
    one worker per pass keeps that start to one per pass.
    """
    if sys.platform.startswith("linux"):
        return multiprocessing.get_context("fork")
    return multiprocessing.get_context()


def files_kept_by_patterns(
    items: Sequence[Tuple[str, str]], patterns: Sequence[Tuple[str, int]]
) -> List[str]:
    """The files of ``items`` whose relative text no pattern of ``patterns`` is found in.

    ``items`` pairs each file with the text the patterns are searched in (its
    path relative to the scan root, as the baseline wrote them); ``patterns``
    are ``(text, flags)`` pairs of compiled regular expressions, compiled again
    here. The detect-secrets scanner's baseline filter, in the shape
    ``evaluated_within`` can hand to a child process: a compiled pattern is
    rebuilt from its text rather than crossing as an object, and the relative
    paths are computed by the caller, so the child does nothing but search.
    """
    compiled = [re.compile(text, flags) for text, flags in patterns]
    return [
        file
        for file, relative in items
        if not any(pattern.search(relative) for pattern in compiled)
    ]


#: The characters that give a checkov skip path regular-expression meaning. An
#: entry holding none of them is a literal, and ``re.search`` of a literal is
#: linear in the path, so it is searched inline; only an entry with syntax takes
#: the bounded child process (``checkov_skips``).
_REGEX_SYNTAX = re.compile(r"[.*+?^$|()\[\]{}\\]")


def checkov_skips(
    pattern: str,
    absolute: str,
    relative: str,
    timeout: Optional[float] = None,
    budget: Optional[EvaluationBudget] = None,
) -> bool:
    """Whether checkov's ``--skip-path`` ``pattern`` leaves out the file at ``absolute``.

    As checkov 3's ``filter_ignored_paths`` decides it while walking the tree:
    the path of the file, or of any directory above it inside the scan, is left
    out when the pattern, compiled as a regular expression with ``.terraform``
    escaped, is found in it, or when the pattern is a substring of it. A pattern
    that is not a valid regular expression is used only as a substring.

    ``timeout`` is the scanner's ``scan_timeout``: a pattern with
    regular-expression syntax is searched under it, in a child process, and a
    search still running at the deadline raises ScannerError naming the option.
    With a ``budget`` (the suppression pass's, ``EvaluationBudget``) the search
    gets what is left of the pass's one scan_timeout and an entry that ran out is
    not searched again; without one the search is bounded on its own
    (``evaluated_within``). A ``timeout`` of None (the scanner left unbounded)
    searches in the child under the scanners' default scan_timeout
    (``_unbounded_ceiling``): the pattern is the client's, so it gets a
    deadline, and inline it would hold this process's interpreter lock for the
    whole search.
    A literal pattern, or one that did not compile, is searched inline.
    """
    candidates = [absolute]
    parts = [part for part in _slashed(relative).split("/") if part]
    base = absolute[: len(absolute) - len("/".join(parts))].rstrip("/")
    for end in range(1, len(parts)):
        candidates.append(f"{base}/{'/'.join(parts[:end])}")
    compiled = _checkov_pattern(pattern)

    if compiled is None or _REGEX_SYNTAX.search(pattern) is None:
        return _checkov_search(pattern, candidates)
    source = (
        "scanners.checkov.options.skip_path, an entry of a config an MCP client "
        "delivered"
    )
    if budget is None:
        return evaluated_within(timeout, source, _checkov_search, pattern, candidates)
    return budget.evaluate(
        timeout, source, f"skip_path:{pattern}", _checkov_search, pattern, candidates
    )


def _checkov_search(pattern: str, candidates: List[str]) -> bool:
    """Whether ``pattern`` is found in, or is a substring of, any of ``candidates``.

    The search of ``checkov_skips``, a module-level function so the bounded
    evaluation can hand it to a child process (``evaluated_within``), where the
    pattern is compiled again (``_checkov_pattern``, cached per process).
    """
    compiled = _checkov_pattern(pattern)
    return any(
        (compiled is not None and compiled.search(candidate) is not None)
        or pattern in candidate
        for candidate in candidates
    )


@functools.lru_cache(maxsize=1024)
def _checkov_pattern(pattern: str) -> Optional[re.Pattern[str]]:
    """``pattern`` compiled as checkov compiles a skip path, once per pattern.

    None when it is not a regular expression; it is then used as a substring
    only, as checkov does. Compiled per candidate path before, for every
    finding. The pattern is the client's and runs in ASH's own process; the
    compile is cached here, and the search bounded by the scanner's
    ``scan_timeout`` (``checkov_skips``).

    ``re.compile`` refuses a malformed pattern with ``re.error``, a repetition
    count past its limit (``a{4294967296}``) with ``OverflowError``, and a
    nesting deeper than the parser's recursion with ``RecursionError``, and a
    pattern whose compiled form does not fit in memory with ``MemoryError``.
    Only the first was caught, so the others escaped ``checkov_skips`` into the
    suppression pass and failed it after the scan had run; every shape the
    compiler refuses is read as a substring, as checkov reads a pattern it
    cannot compile.
    """
    try:
        return re.compile(pattern.replace(".terraform", r"\.terraform"))
    except (re.error, OverflowError, RecursionError, MemoryError):
        return None


def _slashed(text: str) -> str:
    """``text`` with ``/`` for each backslash, where a backslash separates segments.

    That is on Windows. On POSIX a backslash is a character of a file's name,
    and the SARIF step keeps it (``utils/sarif_utils._with_slash_separators``),
    so a finding's path arrives with it. Rewritten to ``/`` here before, the
    POSIX file ``a\\b.py`` was matched as ``a/b.py``: a client ``b.py`` entry
    hid it, though its scanner had read the whole name. ``bandit_would_skip``
    reads the finding's paths through this too, so it matches bandit's globs
    against the name bandit walked.
    """
    return text.replace("\\", "/") if os.sep == "\\" else text


def _components_match(pattern_parts: Sequence[str], path_parts: Sequence[str]) -> bool:
    """Whether glob components match path components end to end.

    ``**`` takes any run of components, none included; every other component
    matches exactly one path component with ``fnmatchcase``, so ``*`` and ``?``
    never cross a ``/``.

    Evaluated as the set of path positions each pattern component can reach,
    left to right: a ``**`` reaches every position from the earliest one
    reached so far to the end, and any other component advances each reached
    position by one when it matches the component there. That is linear in the
    pattern and the path. A recursive match tried every split at every ``**``,
    which a delivered pattern of repeated ``**`` turned into billions of calls
    against a deep path, for every finding and every entry; consecutive ``**``
    are also one ``**`` here, since a run of them takes the same runs.
    """
    pattern: List[str] = []
    for part in pattern_parts:
        if part == "**" and pattern and pattern[-1] == "**":
            continue
        pattern.append(part)
    reached = {0}
    for part in pattern:
        if part == "**":
            reached = set(range(min(reached), len(path_parts) + 1))
        else:
            reached = {
                position + 1
                for position in reached
                if position < len(path_parts)
                and fnmatch.fnmatchcase(path_parts[position], part)
            }
        if not reached:
            return False
    return len(path_parts) in reached


def trivy_path_matches(pattern: str, relative: str) -> bool:
    """Whether a ``.trivyignore.yaml`` entry's ``paths`` glob names the file at ``relative``.

    trivy matches each such glob against the file's path from the scan root,
    whole and anchored, with doublestar semantics: ``vendor/**`` is everything
    under the top-level ``vendor``, and ``requirements.txt`` is the top-level
    file alone.
    The any-depth glob of the grep family was used before, so an ID limited to
    one path applied to that name at every depth.
    """
    candidate = _slashed(pattern.strip())
    if not candidate:
        return False
    # Matched as written: a leading ``./`` or ``/`` and a trailing ``/`` were
    # stripped before, so ``./vendor/x`` and ``/vendor/x`` took ``vendor/x`` here,
    # where trivy's whole-glob match takes neither, and the entry hid findings
    # trivy had reported.
    parts = [part for part in _slashed(relative).split("/") if part not in ("", ".")]
    return _components_match(candidate.split("/"), parts)


def glob_excludes(pattern: str, relative: str) -> bool:
    """Whether glob ``pattern`` excludes the file at ``relative`` (from the scan root).

    Read as the tools read their excludes (semgrep and opengrep: gitignore
    syntax; syft: doublestar globs from the root): ``*``, ``?`` and ``[...]``
    match within one path component and never cross ``/``, and ``**`` matches
    any run of components. A pattern with no ``/`` matches a file or directory
    of that name at any depth. A ``/`` inside the pattern, a leading ``/`` or a
    leading ``./`` anchors it at the scan root; a leading ``**/`` leaves it
    unanchored. A trailing ``/`` names a directory: it is matched against the
    directories above the file, never the file itself, so ``build/`` leaves a
    file named ``build`` to its tool (the slash was stripped before matching,
    and the entry then hid findings in such a file, which the tool had scanned
    and reported). A trailing ``/**`` names everything inside the directory,
    as gitignore reads it, and is matched the same way, so ``src/**`` leaves a
    file named ``src`` to its tool too. The ``/`` of that suffix anchors the
    pattern like any other: ``src/**`` is the directory ``src`` at the scan
    root and leaves ``lib/src/a.py`` to its tool (it was unanchored before, the
    suffix having been taken off ahead of the anchor test, and hid findings the
    tool had reported). A match on a directory excludes every file under it.

    Before, ``fnmatch`` matched the pattern against every run of components, so
    ``*`` crossed ``/`` (``src/*.py`` took ``src/a/b.py``) and a ``/`` inside the
    pattern anchored nothing (``src/vendor`` took ``x/src/vendor/a.py``): findings
    the tool had reported were suppressed as if it had excluded them.
    """
    candidate = _slashed(pattern.strip())
    anchored = candidate.startswith("/")
    while candidate.startswith("./"):
        anchored = True
        candidate = candidate[2:]
    directory_only = candidate.endswith("/")
    candidate = candidate.strip("/")
    # Read before the trailing ``/**`` is taken off: ``src/**`` names a ``/``
    # and anchors, as ``src/`` does not, and the bare ``src`` left behind has
    # no ``/`` to show it.
    names_a_slash = "/" in candidate
    while candidate.endswith("/**"):
        # ``src/**`` is everything inside the directory src, as gitignore reads
        # it, and not a file named src, so it is matched as ``src/`` is. As a
        # run of components ``**`` takes none too, and ``src/**`` reached a
        # top-level file named src, and ``**/build/**`` any file named build,
        # which their tools had scanned and reported.
        directory_only = True
        candidate = candidate[: -len("/**")].rstrip("/")
    if candidate.startswith("**/"):
        anchored = False
        while candidate.startswith("**/"):
            candidate = candidate[3:]
    elif names_a_slash:
        anchored = True
    if not candidate:
        return False
    pattern_parts = [part for part in candidate.split("/") if part]
    parts = [part for part in _slashed(relative).split("/") if part not in ("", ".")]
    starts = range(1) if anchored else range(len(parts))
    # The runs tried end at the file itself, or, for a directory pattern, at
    # the last directory above it.
    longest = len(parts) - 1 if directory_only else len(parts)
    for start in starts:
        for end in range(start + 1, longest + 1):
            if _components_match(pattern_parts, parts[start:end]):
                return True
    return False


def _same_trivy_id(rule_id: str, entry: str) -> bool:
    """Whether trivy reads ignore-file ID ``entry`` as finding ``rule_id``'s.

    trivy compares the two exactly (``IgnoreFindings.Match`` keeps looking while
    ``id != finding.ID``), and matches a misconfiguration by its ID and by its
    AVD ID, which the ``AVD-`` prefix tolerance stands for. Folded to upper case
    before, so a ``cve-2020-0001`` line suppressed ``CVE-2020-0001``, a finding
    trivy itself would have reported.
    """

    def bare(value: str) -> str:
        return value.strip().removeprefix("AVD-")

    return bare(rule_id) == bare(entry)


def exclusion_option_at(
    segments: Sequence[str],
) -> Optional[Tuple[ScannerExclusionOption, bool]]:
    """The exclusion option a config path names, and whether it names one entry of it.

    ``segments`` is a path split into keys: ``scanners``, the scanner's key in
    any spelling the plugin lookup reads, ``options``, and the option with ``-``
    or ``_``, then for a list option ``-`` or an index to name one entry.
    """
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    if len(segments) not in (4, 5) or segments[0] != "scanners":
        return None
    if segments[2] != "options":
        return None
    names = plugin_key_lookup_names(str(segments[1]))
    option = str(segments[3]).replace("-", "_")
    for spec in SCANNER_EXCLUSION_OPTIONS:
        if spec.option != option or reduced_plugin_name(spec.scanner) not in names:
            continue
        if len(segments) == 4:
            return spec, False
        last = str(segments[4])
        if spec.kind != "trivy-ignore-file" and (last == "-" or last.isdigit()):
            return spec, True
        return None
    return None


def moves_all_of(spec: ScannerExclusionOption, value: Any, *, entry: bool) -> bool:
    """Whether resolution takes all of ``value``, written at ``spec``'s option, out of it.

    ``strip_client_scanner_exclusions`` moves every list entry that has a path
    pattern and is not the operator's, and leaves the operator's where they are,
    so no client value is left in the option. An entry with no pattern stays,
    so a value holding one is not moved whole. A trivy ignore file that is set
    is replaced by the trusted one. ``entry`` says ``value`` is written as
    entries appended to the list (one, or a list of them, as an appending
    ``--config-overrides`` names them) rather than as the whole option.
    """
    if spec.kind == "trivy-ignore-file":
        return not entry and isinstance(value, str) and bool(value)
    if entry:
        entries = value if isinstance(value, list) else [value]
    elif isinstance(value, list):
        entries = value
    else:
        return False
    return all(_pattern_of(item)[0] is not None for item in entries)


def moved_exclusion_pointers(document: Any) -> List[str]:
    """The JSON pointers of the exclusion options in ``document`` that resolution moves whole.

    For the denied-fields check of a delivered file, which sees the sections as
    the move leaves them (``client_config_policy.apply_client_config_rules``):
    these hold nothing of the client's once the move has run, so the
    always-denied entries that cover a whole scanner section do not refuse them
    (``runtime_patch.SECTION_FLOOR_ENTRIES``). Every other ``denied_paths``
    entry and value pattern still applies, and so does the check of every other
    key of the section.
    """
    from automated_security_helper.config.config_sources import _resolve_dict_key

    scanners = document.get("scanners") if isinstance(document, dict) else None
    if not isinstance(scanners, dict):
        return []
    found: List[str] = []
    for key, section in scanners.items():
        if not isinstance(section, dict):
            continue
        options_key = _resolve_dict_key(section, "options")
        options = section.get(options_key)
        if not isinstance(options, dict):
            continue
        for name, value in options.items():
            segments = ["scanners", str(key), str(options_key), str(name)]
            located = exclusion_option_at(segments)
            if located is None or not moves_all_of(located[0], value, entry=False):
                continue
            found.append(
                "/"
                + "/".join(
                    segment.replace("~", "~0").replace("/", "~1")
                    for segment in segments
                )
            )
    return found


def strip_client_scanner_exclusions(
    config: Any,
    documents: Mapping[Path, Any],
    base: Any,
    *,
    source_dir: Path | str | None,
    scanned_root: Path | str | None,
    is_delivered: Optional[Any] = None,
) -> Any:
    """Move each exclusion a delivered config supplied from its scanner's options to the config.

    In place, on ``config`` (an ``AshConfig`` with a client-delivered file in its
    chain), which is returned. ``base`` is the trusted config.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied
    from automated_security_helper.config.sandbox_grants import working_directory

    delivered = is_delivered or config_is_client_supplied
    operator_documents = [
        (Path(path), document)
        for path, document in documents.items()
        if not delivered(path)
    ]
    # None with no root given and no working directory left: the one use of
    # the root, a delivered trivy ignore file, is then not read.
    delivered_documents = [
        (Path(path), document)
        for path, document in documents.items()
        if delivered(path)
    ]
    named_root = scanned_root or source_dir
    root = Path(named_root) if named_root else working_directory()
    recorded: List[ClientScannerExclusion] = list(
        getattr(config, "_client_scanner_exclusions", None) or []
    )
    warnings: List[str] = list(getattr(config, "_resolution_warnings", None) or [])
    for spec in SCANNER_EXCLUSION_OPTIONS:
        sections = _scanner_sections(config, spec.scanner)
        read_key = _section_the_scanner_reads(sections, spec.scanner)
        # The operator's values are read from the one section spelling the
        # scanner reads in the merged config, as the client's are below.
        operator_entries = _operator_entries(
            spec, operator_documents, base, read_key=read_key
        )
        # Which patterns a file wrote, in any spelling of the scanner's section:
        # the delivered files' are the client's, and the operator files' under a
        # spelling the scanner does not read are the operator's. The merged
        # option holds both, and every entry whose pattern is an operator's was
        # taken for a client copy, so an expired operator entry was blamed on
        # the client in the warning, as was an operator entry under a spelling
        # the scanner never reads.
        spellings = [section_key for section_key, _ in sections]
        client_patterns = _patterns_written(delivered_documents, spec, spellings)
        operator_unread = _patterns_written(
            operator_documents,
            spec,
            [section_key for section_key in spellings if section_key != read_key],
        )
        for key, section in sections:
            options = _options_of(section)
            if options is None:
                continue
            value = _get(options, spec.option)
            # Only the section the scanner reads excluded anything; an entry a
            # delivered file wrote under another spelling is still moved out,
            # so no client value stays in the config, but it is recorded as
            # nothing: it kept no file from the scanner.
            is_read = key == read_key
            if spec.kind == "trivy-ignore-file":
                operator_spelling = (
                    _names_an_operator_file(
                        str(value),
                        operator_entries,
                        inside=[root] + [path.parent for path, _ in operator_documents],
                    )
                    if value
                    else None
                )
                if value and operator_spelling is not None:
                    if operator_spelling != str(value):
                        # Admitted by resolution only: the option names the
                        # operator's file by the operator's path, not by the
                        # client's route to it.
                        _set(options, spec.option, operator_spelling)
                        warnings.append(
                            f"{spec.key}: {str(value)!r} resolves to the operator's "
                            f"ignore file and is replaced by its path "
                            f"{operator_spelling!r}."
                        )
                elif value:
                    trusted = _operator_ignore_file(
                        spec, operator_documents, base, read_key=read_key
                    )
                    _set(options, spec.option, trusted)
                    if not is_read:
                        warnings.append(
                            f"{spec.key}: {str(value)!r} came from a config an MCP "
                            f"client delivered, under scanners.{key}, a section the "
                            f"{spec.scanner} scanner does not read, so it excluded "
                            "nothing and its entries are not applied."
                        )
                        continue
                    found, note = _trivy_ignore_exclusions(
                        str(value), spec, source_dir=source_dir, root=root
                    )
                    recorded.extend(found)
                    warnings.append(note)
                continue
            if not isinstance(value, list):
                continue
            kept: List[Any] = []
            moved: List[ClientScannerExclusion] = []
            expired: List[str] = []
            expired_by_operator: List[str] = []
            unread: List[str] = []
            unread_operator: List[str] = []
            replaced = 0
            for entry in value:
                pattern, reason, expiration = _entry_fields(entry)
                if pattern is None:
                    kept.append(entry)
                    continue
                if pattern in operator_entries:
                    # The operator's own entry, with its reason and expiration,
                    # not the client's copy of the path: a client could otherwise
                    # revive an exclusion the operator let expire. An operator
                    # entry that has expired drops the client's copy whatever
                    # shape the option holds it in: the scanner would not apply
                    # it, and a copy kept in a shape that carries no expiration
                    # (a plain string) would have applied for good.
                    operator_entry = operator_entries[pattern]
                    operator_expiration = _entry_fields(operator_entry)[2]
                    if _entry_expired(operator_expiration):
                        # The client's, when a delivered file wrote it or the
                        # option holds the path with terms other than the
                        # operator's (an override, which no file carries): an
                        # operator entry nobody else touched is dropped all the
                        # same (the scanner would not apply it) but not blamed
                        # on the client.
                        if pattern in client_patterns or _expiration_day(
                            expiration
                        ) != _expiration_day(operator_expiration):
                            expired.append(pattern)
                        else:
                            expired_by_operator.append(pattern)
                        continue
                    spelled = _spelled_like(entry, operator_entry)
                    if spelled != entry:
                        replaced += 1
                    kept.append(spelled)
                    continue
                if _entry_expired(expiration):
                    # The scanner would not apply it (active_ignore_paths), so
                    # there is nothing to mark after the scan either.
                    expired.append(pattern)
                    continue
                if not is_read:
                    if pattern in operator_unread and pattern not in client_patterns:
                        unread_operator.append(pattern)
                    else:
                        unread.append(pattern)
                    continue
                moved.append(
                    ClientScannerExclusion(
                        scanner=spec.scanner,
                        option=spec.option,
                        kind=spec.kind,
                        pattern=pattern,
                        reason=reason or "set by a config an MCP client delivered",
                        scan_timeout=_scan_timeout_of(options),
                    )
                )
            if not (
                moved
                or expired
                or expired_by_operator
                or unread
                or unread_operator
                or replaced
            ):
                continue
            # Written back whenever an entry changed, a client's copy of an
            # operator entry replaced by the operator's own included: left
            # unwritten, the client's reason and expiration stayed in the option.
            _set(options, spec.option, kept)
            recorded.extend(moved)
            if moved:
                listed = ", ".join(repr(item.pattern) for item in moved)
                warnings.append(
                    f"{spec.key}: {listed} came from a config an MCP client delivered "
                    f"and {'is' if len(moved) == 1 else 'are'} not applied as an "
                    f"exclusion. The files are scanned, and each {spec.scanner} "
                    f"finding {'it' if len(moved) == 1 else 'they'} would have left "
                    "out is reported suppressed and marked client-supplied."
                )
            if expired:
                listed = ", ".join(repr(pattern) for pattern in expired)
                warnings.append(
                    f"{spec.key}: {listed} came from a config an MCP client delivered "
                    f"and {'has' if len(expired) == 1 else 'have'} expired (by "
                    f"{'its' if len(expired) == 1 else 'their'} own expiration, or "
                    "the operator entry of the same path has), so "
                    f"{'it is' if len(expired) == 1 else 'they are'} not applied: "
                    f"the {spec.scanner} scanner would not have applied "
                    f"{'it' if len(expired) == 1 else 'them'}, and the files are "
                    "scanned."
                )
            if unread:
                listed = ", ".join(repr(pattern) for pattern in unread)
                warnings.append(
                    f"{spec.key}: {listed} came from a config an MCP client delivered "
                    f"under scanners.{key}, a section the {spec.scanner} scanner "
                    f"does not read, so {'it' if len(unread) == 1 else 'they'} "
                    f"excluded nothing and {'is' if len(unread) == 1 else 'are'} "
                    "not applied."
                )
            if expired_by_operator:
                listed = ", ".join(repr(pattern) for pattern in expired_by_operator)
                many = len(expired_by_operator) != 1
                warnings.append(
                    f"{spec.key}: {listed} {'have' if many else 'has'} expired in "
                    f"the operator's own config, so {'they are' if many else 'it is'} "
                    f"not applied: the {spec.scanner} scanner would not have applied "
                    f"{'them' if many else 'it'}, and the files are scanned."
                )
            if unread_operator:
                listed = ", ".join(repr(pattern) for pattern in unread_operator)
                many = len(unread_operator) != 1
                warnings.append(
                    f"{spec.key}: {listed} {'are' if many else 'is'} written in an "
                    f"operator file under scanners.{key}, a section the "
                    f"{spec.scanner} scanner does not read, so "
                    f"{'they excluded' if many else 'it excluded'} nothing and "
                    f"{'are' if many else 'is'} not applied."
                )
    config._client_scanner_exclusions = _unique(recorded)
    config._resolution_warnings = warnings
    return config


def _patterns_written(
    documents: Sequence[Tuple[Path, Any]],
    spec: ScannerExclusionOption,
    spellings: Sequence[str],
) -> Set[str]:
    """The patterns ``documents`` write at ``spec``'s option under any of ``spellings`` of its scanner's section."""
    found: Set[str] = set()
    for _path, document in documents:
        for spelling in spellings:
            for value in _document_values(document, spec, spelling):
                found |= _patterns_in(value)
    return found


def _unique(items: Iterable[ClientScannerExclusion]) -> List[ClientScannerExclusion]:
    seen: Set[ClientScannerExclusion] = set()
    out: List[ClientScannerExclusion] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _scanner_sections(config: Any, scanner: str) -> List[Tuple[str, Any]]:
    """Each section of ``config.scanners`` that ``get_plugin_config(scanner)`` could read."""
    from automated_security_helper.config.ash_config import (
        plugin_key_lookup_names,
        reduced_plugin_name,
    )

    segment = config.scanners
    by_key = {
        (field.alias or name): name
        for name, field in type(segment).model_fields.items()
    }
    extra = segment.__pydantic_extra__ or {}
    wanted = reduced_plugin_name(scanner)
    found: List[Tuple[str, Any]] = []
    for key in list(by_key) + list(extra):
        if key != scanner and wanted not in plugin_key_lookup_names(key):
            continue
        section = getattr(segment, by_key[key]) if key in by_key else extra.get(key)
        if section is not None:
            found.append((key, section))
    return found


def _options_of(section: Any) -> Any:
    if isinstance(section, dict):
        from automated_security_helper.config.config_sources import _resolve_dict_key

        key = _resolve_dict_key(section, "options")
        options = section.get(key)
        return options if isinstance(options, (dict, BaseModel)) else None
    return getattr(section, "options", None)


def _get(options: Any, option: str) -> Any:
    if isinstance(options, dict):
        from automated_security_helper.config.config_sources import _resolve_dict_key

        return options.get(_resolve_dict_key(options, option))
    return getattr(options, option, None)


def _set(options: Any, option: str, value: Any) -> None:
    if isinstance(options, dict):
        from automated_security_helper.config.config_sources import _resolve_dict_key

        options[_resolve_dict_key(options, option)] = value
    else:
        setattr(options, option, value)


# The largest scan_timeout the pattern bound waits for, in seconds: about 24.8
# days, far past any scan. The wait behind the bound takes its timeout within a
# limit of its platform (a C int of milliseconds for a poll on a pipe,
# ``threading.TIMEOUT_MAX`` for a lock), and this ceiling sits under each.
_LARGEST_SCAN_TIMEOUT = 2_147_483.0


def _unbounded_ceiling() -> float:
    """The seconds a client's pattern is given when its scanner's scan_timeout is null.

    The scanners' default ``scan_timeout``, or ``_LARGEST_SCAN_TIMEOUT`` if the
    default is ever not a number in range. The operator who sets a scanner's
    timeout to null leaves the scanner's own tool unbounded; a pattern a client
    delivered and ASH searches in its own process is held to a deadline of
    ASH's choosing, whatever that setting says.
    """
    from automated_security_helper.base.options import ScannerOptionsBase

    default = ScannerOptionsBase.model_fields["scan_timeout"].default
    if (
        isinstance(default, (int, float))
        and not isinstance(default, bool)
        and 0 < default <= _LARGEST_SCAN_TIMEOUT
    ):
        return float(default)
    return _LARGEST_SCAN_TIMEOUT


def _scan_timeout_of(options: Any) -> Optional[float]:
    """The section's ``scan_timeout`` as the scanner will run under it.

    The value the section sets; the scanners' default for a plain mapping that
    leaves it unset, or for a value that is not a finite positive number up to
    ``_LARGEST_SCAN_TIMEOUT``; None for an explicit null, the scanner left
    unbounded. The scanners' own validation (``ScannerOptionsBase.scan_timeout``,
    an integer of at least 1 with no upper bound) refuses a non-positive value
    but admits any size, so a validated model with a timeout past the ceiling
    runs its scanner that long while the bound here takes the default, the
    conservative side. A plain mapping gets no model validation at all, so an
    infinite value (YAML ``.inf``), a NaN or one past what the bound's wait can
    take arrived as written and reached that wait, which raised in the
    suppression pass after the scan.
    """
    from automated_security_helper.base.options import ScannerOptionsBase

    default = ScannerOptionsBase.model_fields["scan_timeout"].default
    if isinstance(options, dict):
        from automated_security_helper.config.config_sources import _resolve_dict_key

        key = _resolve_dict_key(options, "scan_timeout")
        if key not in options:
            return default
        value = options[key]
    else:
        value = getattr(options, "scan_timeout", default)
    if value is None:
        return None
    # The two comparisons admit every finite number in range and refuse an
    # infinity, with no float conversion an oversized integer could overflow;
    # a NaN passes both, and is the one value unequal to itself.
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value <= 0
        or value > _LARGEST_SCAN_TIMEOUT
        or value != value
    ):
        return default
    return value


def _pattern_of(entry: Any) -> Tuple[Optional[str], Optional[str]]:
    """An option entry's pattern and reason: a string, or a path-with-reason entry.

    A mapping entry is read as any ``Mapping``, as ``_entry_fields`` and
    ``_operator_fields`` read one, so an entry held in a mapping type that is
    not a ``dict`` is the same entry to every reading (a ``dict``-only test
    here left ``_entry_fields`` reading its expiration from an entry whose
    pattern this function had not found).
    """
    if isinstance(entry, str):
        return entry, None
    if isinstance(entry, Mapping):
        path = entry.get("path")
        reason = entry.get("reason")
        return (path if isinstance(path, str) else None), (
            reason if isinstance(reason, str) else None
        )
    path = getattr(entry, "path", None)
    reason = getattr(entry, "reason", None)
    return (path if isinstance(path, str) else None), (
        reason if isinstance(reason, str) else None
    )


def _patterns_in(value: Any) -> Set[str]:
    if isinstance(value, str):
        return {value}
    if not isinstance(value, list):
        return set()
    found: Set[str] = set()
    for entry in value:
        pattern, _ = _pattern_of(entry)
        if pattern is not None:
            found.add(pattern)
    return found


def _entry_fields(entry: Any) -> Tuple[Optional[str], Optional[str], Any]:
    """An option entry's pattern, reason and expiration (a string, or a path-with-reason entry).

    A mapping entry is read as any ``Mapping``, as ``_operator_fields`` reads an
    operator's, so the two readings of one entry agree.
    """
    pattern, reason = _pattern_of(entry)
    if isinstance(entry, Mapping):
        return pattern, reason, entry.get("expiration")
    if isinstance(entry, str):
        return pattern, reason, None
    return pattern, reason, getattr(entry, "expiration", None)


def _expiration_day(expiration: Any) -> Optional[str]:
    """An entry's expiration as its YYYY-MM-DD day, None for none.

    A YAML date, a validated model's text and a timestamp read alike, so two
    spellings of one day compare equal.
    """
    return str(expiration)[:10] if expiration else None


def _entry_expired(expiration: Any) -> bool:
    """Whether an entry with this ``expiration`` no longer applies, as the scanners read it.

    The one rule of ``utils/suppression_matcher._has_expired``: a YYYY-MM-DD date
    that has passed, by the host's local date, and a date that does not parse
    counts as expired too (the entry is then not applied, which scans more).
    """
    if not expiration:
        return False
    from automated_security_helper.models.core import expiration_has_passed

    try:
        return expiration_has_passed(str(expiration)[:10])
    except ValueError:
        return True


def _operator_fields(source: Any) -> Optional[Dict[str, Any]]:
    """The operator's entry ``source`` as the fields of a path-with-reason entry.

    A mapping is its own fields, with a YAML date (an unquoted 2099-01-31, which
    arrives as a date object) as the YYYY-MM-DD text the model's expiration
    holds; a string is an entry of that path alone, with no reason and no
    expiration. None for any other shape.
    """
    if isinstance(source, Mapping):
        return {
            key: value.isoformat() if isinstance(value, date) else value
            for key, value in source.items()
        }
    if isinstance(source, str):
        return {"path": source}
    return None


def _spelled_like(template: Any, source: Any) -> Any:
    """The operator's entry ``source`` in the shape ``template`` has in the option.

    The option holds strings, mappings or validated models; the operator's entry
    comes as a string or a mapping from a document or the trusted config's dump.
    The result carries the operator's fields, its path, reason and expiration,
    in the template's shape: an operator mapping under a plain-string option is
    its path, an operator string under a mapping or model option is an entry of
    that path alone, and a model the operator's fields do not validate as on
    their own keeps the template's other fields under the operator's
    (``model_copy``). The client's own copy was kept whenever the shapes
    differed or the model refused the fields, so a client string stood in for an
    operator mapping with the operator's expiration lost, and a client model
    kept its own reason and expiration under an operator string.
    """
    if isinstance(template, BaseModel):
        if isinstance(source, BaseModel):
            return source
        fields = _operator_fields(source)
        if fields is None:
            return template
        try:
            return type(template).model_validate(fields)
        except Exception:  # noqa: BLE001 -- the operator's fields alone are not a model
            try:
                # An operator string names no expiration: the entry does not
                # expire, so the client's expiration goes with its reason kept.
                return template.model_copy(update={"expiration": None, **fields})
            except Exception:  # noqa: BLE001 -- keep the option well typed
                return template
    if isinstance(template, Mapping):
        # Any mapping, as ``_entry_fields`` reads one: a mapping that is not a
        # ``dict`` fell through to the template and kept the client's own
        # reason and expiration under an operator entry.
        if isinstance(source, BaseModel):
            return source.model_dump(exclude_unset=True)
        fields = _operator_fields(source)
        return template if fields is None else fields
    if isinstance(template, str):
        if isinstance(source, str):
            return source
        path, _ = _pattern_of(source)
        return template if path is None else path
    return template


def _section_the_scanner_reads(
    sections: List[Tuple[str, Any]], scanner: str
) -> Optional[str]:
    """The key of the one section ``get_plugin_config(scanner)`` reads among ``sections``.

    As ``plugin_section_lookup`` chooses it: the scanner's own name when it is
    a key, else the key spelled as its reduced name, else the first key that
    claims it (``plugin_section_key``). Every other section of the scanner's
    name is never read by the scanner, so an exclusion written there excluded
    nothing.
    """
    from automated_security_helper.config.ash_config import (
        plugin_section_key,
        reduced_plugin_name,
    )

    keys = [key for key, _ in sections]
    if scanner in keys:
        return scanner
    return plugin_section_key(keys, reduced_plugin_name(scanner))


def _names_an_operator_file(
    value: str,
    operator_entries: Mapping[str, Any],
    *,
    inside: Sequence[Optional[Path]] = (),
) -> Optional[str]:
    """The spelling the option keeps when trivy ``ignore_file`` ``value`` names an operator file, else None.

    The merged config holds the path as the loader anchored it (absolute, from
    the config file's directory), while an operator document holds the text the
    operator wrote, so the two are compared in every spelling: as written, as a
    POSIX path, and resolved. ``operator_entries`` holds, for each operator
    document's value, the text and its resolutions (``_operator_entries``).

    A value that matches as text is answered with the operator's file as the
    option holds it: the document's text anchored at that document's
    directory (``operator_entries`` stores it so). An absolute text is its own
    answer, so the value is kept. A relative text is not: kept relative, the
    option names a file by a base trivy resolves against its own working
    directory, which can be the scanned tree, where the client's own file of
    that name would apply unmarked.
    A value that matches only once resolved (a link, or another route to the
    operator's file) is answered with the operator's resolved path instead:
    the option then names the operator's file directly, and the tool, which
    opens the option's value by name later, never follows a path a client
    chose. Resolving it here and opening the client's spelling later would be
    a check the client could change between the two.

    Resolving touches the file system, and the value is the client's: a UNC
    path makes Windows connect to the named host, and a path on a hung network
    mount blocks the resolution. So the value is resolved only when, read
    lexically (``..`` folded, no link followed), it lies under one of the
    ``inside`` directories: the scanned root and the operator documents'
    directories, the places an operator file can be. The gate is lexical, so
    a value under one of them that is itself a link the client placed is
    resolved too; that is the case this branch exists for, a client link to
    the operator's file, and the resolve stays inside the tree it may read.
    A value elsewhere is compared as text only, and when the text matches
    nothing it takes the operator's own file by the caller's next branch, as
    any other client value.
    """
    if value in operator_entries:
        return str(operator_entries[value])
    posix = Path(value).as_posix()
    if posix in operator_entries:
        return str(operator_entries[posix])
    if not _lexically_under(value, inside):
        return None
    try:
        resolved = Path(value).resolve().as_posix()
    except (OSError, RuntimeError, ValueError):
        return None
    if resolved in operator_entries:
        return resolved
    return None


def _lexically_under(value: str, directories: Sequence[Optional[Path]]) -> bool:
    """Whether ``value``, with ``..`` folded and no link followed, is under one of ``directories``.

    Both sides are normalized the same way (``os.path.normpath``); a relative
    value is read against the current directory, as ``Path.resolve`` would
    read it. A UNC or drive-prefixed value under none of the directories is
    False, as is any value when no directory is given.
    """
    try:
        candidate = Path(os.path.normpath(os.path.abspath(value)))
    except (OSError, ValueError):
        return False
    for directory in directories:
        if directory is None:
            continue
        try:
            root = Path(os.path.normpath(os.path.abspath(str(directory))))
        except (OSError, ValueError):
            continue
        if candidate == root or root in candidate.parents:
            return True
    return False


def _operator_entries(
    spec: ScannerExclusionOption,
    operator_documents: List[Tuple[Path, Any]],
    base: Any,
    read_key: Optional[str] = None,
) -> Dict[str, Any]:
    """The entries the operator supplied for ``spec``, by pattern: defaults, the trusted config, operator files.

    The defaults and the trusted config come first and keep a pattern they
    hold. Among the files of the chain the last entry seen for a pattern wins,
    as the chain itself is last-writer-wins: the first was kept before, so a
    pattern a later file let expire or changed was still the earlier file's
    unexpired entry here, and a client's copy of it was respelled as that entry
    and kept. For a trivy ignore file the keys also hold each value resolved
    from its document's directory, so a relative operator value compares with
    the anchored absolute path the merged config holds.
    """
    from automated_security_helper.config.operator_paths import anchored_path

    found: Dict[str, Any] = {pattern: pattern for pattern in spec.default}
    written_by_a_file: Set[str] = set()

    def put(key: str, entry: Any, from_a_file: bool) -> None:
        if key not in found or (from_a_file and key in written_by_a_file):
            found[key] = entry
            if from_a_file:
                written_by_a_file.add(key)

    def take(value: Any, directory: Optional[Path], from_a_file: bool = False) -> None:
        if spec.kind == "trivy-ignore-file":
            text = _path_text(value)
            if text:
                # What the option holds for this file: the text anchored at the
                # document's directory, as the loader anchors it. A relative
                # text kept as it was is not the operator's file once it
                # reaches trivy, whose base is not that directory.
                held = (
                    text
                    if directory is None
                    else anchored_path(text, directory, expands_variables=False)
                )
                put(text, held, from_a_file)
                put(Path(text).as_posix(), held, from_a_file)
                anchored = Path(text) if directory is None else directory / text
                try:
                    put(anchored.resolve().as_posix(), held, from_a_file)
                except (OSError, RuntimeError, ValueError):
                    pass
            return
        if isinstance(value, str):
            put(value, value, from_a_file)
            return
        if not isinstance(value, list):
            return
        for entry in value:
            pattern, _ = _pattern_of(entry)
            if pattern is not None:
                put(pattern, entry, from_a_file)

    read = base.get_plugin_config("scanner", spec.scanner) if base is not None else None
    if isinstance(read, dict):
        take(_get(read.get("options") or {}, spec.option), None)
    for path, document in operator_documents:
        for value, whole in _document_writes(document, spec, read_key):
            if whole:
                # The chain replaces a list whole, so a file that writes the
                # option takes away every entry an earlier file gave it: a
                # pattern this file left out is no longer the operator's, and
                # a client's copy of it is the client's again, not the earlier
                # file's entry respelled and kept.
                for key in written_by_a_file:
                    found.pop(key, None)
                written_by_a_file.clear()
            take(value, Path(path).parent, from_a_file=True)
    return found


def _document_values(
    document: Any, spec: ScannerExclusionOption, read_key: Optional[str] = None
) -> List[Any]:
    """The values one chain file writes at ``spec``'s option, in the file's order.

    See ``_document_writes``, which also says which of them write the option
    whole.
    """
    return [value for value, _ in _document_writes(document, spec, read_key)]


def _document_writes(
    document: Any, spec: ScannerExclusionOption, read_key: Optional[str] = None
) -> List[Tuple[Any, bool]]:
    """Each value one chain file writes at ``spec``'s option, in the file's order, with whether it writes the option whole.

    A value written whole replaces the option (a section or an ``options``
    object that holds the option, or an operation at the option itself); an
    operation that appends or sets one entry (its pointer ends in ``-`` or an
    index) adds to what earlier files gave the option, and a section that does
    not hold the option at all writes nothing. The value of such a section is
    returned as None, not whole.

    Each value under the one ``scanners`` section the scanner reads, then each
    value a ``patch`` operation of the file writes there
    (``config_sources.PATCH_KEY``): a file of the chain may carry its changes as
    JSON-patch operations, and ``documents`` holds the file as written. Read
    from ``scanners`` alone before, an operator file's patched-in entries were
    nobody's: a client entry repeating one was moved out and marked, and a
    client copy of one the operator let expire revived it. An operation that
    appends one entry (its pointer ends in ``-`` or an index) is returned as a
    one-entry list.

    ``read_key`` is the section key the scanner reads in the merged config
    (``_section_the_scanner_reads``); with none given, it is chosen among the
    file's own spellings by the same rule. Every other spelling of the scanner's
    name is a section the scanner never reads, so a value written there is not
    the operator's exclusion: collected from every spelling before, an
    ``ignore_file`` under a section trivy never reads was restored as the
    operator's, while a client value under such a spelling counts as nothing.

    An operation may also write the option from above: the whole ``options``
    object, the whole scanner section, or the whole ``scanners`` map. Only an
    operation at the option itself, or at one of its entries, was read before,
    so an operator's entries written by such an operation were credited to no
    one, which is the shape this reader exists to credit.
    """
    from automated_security_helper.config.ash_config import (
        _lookup_spelling,
        plugin_key_lookup_names,
        reduced_plugin_name,
    )
    from automated_security_helper.config.config_sources import PATCH_KEY

    if not isinstance(document, dict):
        return []
    wanted = reduced_plugin_name(spec.scanner)

    def names_the_scanner(key: Any) -> bool:
        return key == spec.scanner or wanted in plugin_key_lookup_names(str(key))

    scanners = document.get("scanners")
    operations: List[Tuple[List[str], Any]] = []
    ops = document.get(PATCH_KEY)
    for op in ops if isinstance(ops, list) else []:
        if not isinstance(op, dict) or "value" not in op:
            continue
        if op.get("op") not in ("add", "replace"):
            continue
        pointer = op.get("path")
        if not isinstance(pointer, str) or not pointer.startswith("/"):
            continue
        segments = [
            part.replace("~1", "/").replace("~0", "~")
            for part in pointer[1:].split("/")
        ]
        operations.append((segments, op["value"]))

    if read_key is None:
        spellings: List[str] = []
        if isinstance(scanners, dict):
            spellings.extend(str(key) for key in scanners)
        for segments, value in operations:
            if segments == ["scanners"] and isinstance(value, dict):
                spellings.extend(str(key) for key in value)
            elif len(segments) >= 2 and segments[0] == "scanners":
                spellings.append(segments[1])
        candidates = [
            (key, None) for key in dict.fromkeys(spellings) if names_the_scanner(key)
        ]
        read_key = _section_the_scanner_reads(candidates, spec.scanner)
    if read_key is None:
        return []

    def is_read(key: Any) -> bool:
        return key == read_key or _lookup_spelling(str(key)) == _lookup_spelling(
            read_key
        )

    def holds_the_option(options: Dict[Any, Any]) -> bool:
        from automated_security_helper.config.config_sources import _resolve_dict_key

        return _resolve_dict_key(options, spec.option) in options

    def option_of(options: Dict[Any, Any]) -> Tuple[Any, bool]:
        return _get(options, spec.option), holds_the_option(options)

    def option_of_section(section: Any) -> List[Tuple[Any, bool]]:
        options = _options_of(section) if isinstance(section, dict) else None
        return [option_of(options)] if isinstance(options, dict) else []

    values: List[Tuple[Any, bool]] = []
    if isinstance(scanners, dict):
        for key, section in scanners.items():
            if is_read(key):
                values.extend(option_of_section(section))
    for segments, value in operations:
        if segments == ["scanners"]:
            if isinstance(value, dict):
                for key, section in value.items():
                    if is_read(key):
                        values.extend(option_of_section(section))
            continue
        if len(segments) < 2 or segments[0] != "scanners" or not is_read(segments[1]):
            continue
        if len(segments) == 2:
            values.extend(option_of_section(value))
            continue
        if len(segments) == 3 and segments[2] == "options":
            if isinstance(value, dict):
                values.append(option_of(value))
            continue
        located = exclusion_option_at(segments)
        if located is None or located[0] != spec:
            continue
        values.append(
            (
                [value] if located[1] and not isinstance(value, list) else value,
                not located[1],
            )
        )
    return values


def _path_text(value: Any) -> Optional[str]:
    """A trivy ``ignore_file`` value as text, or None when it names no file.

    The option is typed ``Path | str | None``, and the trusted config's dump
    hands a Path back as a Path. Read as a string alone before, a Path was
    neither the operator's own file nor the trusted value to restore, so the
    operator's ignore file was replaced with None.
    """
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str) and value:
        return value
    return None


def _trusted_ignore_file(base: Any, spec: ScannerExclusionOption) -> Optional[str]:
    read = base.get_plugin_config("scanner", spec.scanner) if base is not None else None
    if isinstance(read, dict):
        return _path_text(_get(read.get("options") or {}, spec.option))
    return None


def _operator_ignore_file(
    spec: ScannerExclusionOption,
    operator_documents: List[Tuple[Path, Any]],
    base: Any,
    read_key: Optional[str] = None,
) -> Optional[str]:
    """The ``ignore_file`` the option holds once a delivered value is taken out of it.

    The value of the last file of the chain that no client delivered and sets
    the option, a relative one anchored at that file's directory as the loader
    anchors it (``operator_paths.anchored_path``); with none, the trusted
    config's. The trusted config's value alone was restored before, so an
    ignore file an operator file of the chain set was dropped whenever a
    delivered file overrode the option.
    """
    from automated_security_helper.config.operator_paths import anchored_path

    found: Optional[str] = None
    for path, document in operator_documents:
        for value in _document_values(document, spec, read_key):
            text = _path_text(value)
            if text:
                found = anchored_path(text, Path(path).parent, expands_variables=False)
    if found is not None:
        return found
    return _trusted_ignore_file(base, spec)


def _trivy_ignore_exclusions(
    value: str,
    spec: ScannerExclusionOption,
    *,
    source_dir: Path | str | None,
    root: Optional[Path],
) -> Tuple[List[ClientScannerExclusion], str]:
    """The entries of the trivy ignore file a delivered config named, and a warning saying so.

    The file is read only as a regular file inside ``root``, the tree being
    scanned, through ``utils/scanned_tree.open_in_scanned_tree``: no ``..``, no
    symlink at any component, one hard link, and read from the descriptor that
    was checked. A wider test (any checkout above the tree, any session's
    delivered files) would let a delivered config pick a file elsewhere on the
    server and see parts of it in the results. Nothing read from a file is
    put in a warning. With no ``root`` (no scanned root, no source directory
    and no working directory) there is no tree to read it from, so it is not
    read and no entry is applied.
    """
    from automated_security_helper.utils.scanned_tree import (
        TreeInputRefused,
        open_in_scanned_tree,
    )

    lead = (
        f"{spec.key}: {value!r} came from a config an MCP client delivered and is not "
        f"passed to trivy."
    )
    if root is None:
        return [], (
            f"{lead} It was not read, and its entries are not applied: there is "
            f"no scanned tree to read it from (the working directory is gone), "
            f"and only a regular file inside the scanned tree is read."
        )
    path = Path(value)
    if not path.is_absolute():
        path = Path(source_dir or root) / path
    try:
        handle = open_in_scanned_tree(path, root)
    except TreeInputRefused as refused:
        return [], (
            f"{lead} It was not read, and its entries are not applied: "
            f"{refused.reason}, and only a regular file inside the scanned tree is "
            f"read."
        )
    except (OSError, ValueError):
        # ValueError: a NUL character in the value (os.open refuses an embedded
        # null byte), which escaped as an uncaught error and ended resolution.
        return [], f"{lead} It could not be read, so no entries are applied."
    with handle:
        data = handle.read(_MAX_IGNORE_FILE_BYTES + 1)
    if len(data) > _MAX_IGNORE_FILE_BYTES:
        return [], (
            f"{lead} It is larger than {_MAX_IGNORE_FILE_BYTES} bytes, so its "
            f"entries are not applied."
        )
    text = data.decode("utf-8", errors="replace")
    try:
        entries = parse_trivy_ignore_file(
            text, yaml_format=path.suffix in (".yaml", ".yml")
        )
    except ValueError:
        return [], f"{lead} It could not be parsed, so no entries are applied."
    reason = f"listed in the ignore file {value!r} a client-delivered config named"
    found = [
        ClientScannerExclusion(
            scanner=spec.scanner,
            option=spec.option,
            kind=spec.kind,
            pattern=entry_id,
            reason=reason,
            paths=paths,
        )
        for entry_id, paths in entries
    ]
    return found, (
        f"{lead} Its {len(found)} entr{'y is' if len(found) == 1 else 'ies are'} "
        f"applied after the scan: each trivy finding one names is reported suppressed "
        f"and marked client-supplied."
    )


def parse_trivy_ignore_file(
    text: str, *, yaml_format: bool, today: Optional[date] = None
) -> List[Tuple[str, Tuple[str, ...]]]:
    """(ID, paths) for each unexpired entry of a trivy ignore file.

    The plain format has one ID per line, read as trivy reads it: a line whose
    first field starts with ``#`` is a comment, the first field of any other
    line is the ID, and an ``exp:YYYY-MM-DD`` field anywhere after it sets the
    day from which the entry no longer applies. A ``#`` later in the line is
    text, not a comment: the line was cut at its first ``#`` before, so
    ``CVE-X # exp:2020-01-01`` lost its expiry and applied, while trivy reads
    the field and drops the expired entry. The field is read whole: anything but
    a plain YYYY-MM-DD date (``2099-01-01T00:00``, ``2099-01-01x``) makes the
    file unreadable (ValueError), where trivy logs the line and skips only it.
    That divergence is deliberate and errs toward reporting: no entry of an
    unreadable file is applied, so every finding it names stays reported,
    the entries trivy would still have honored included. The YAML format
    (``.trivyignore.yaml``)
    lists entries with ``id``, optional ``paths`` and optional ``expired_at``
    under ``vulnerabilities``, ``misconfigurations``, ``secrets`` and
    ``licenses``.
    """
    today = today or date.today()
    found: List[Tuple[str, Tuple[str, ...]]] = []
    if yaml_format:
        import yaml

        from automated_security_helper.config.ash_config import load_config_yaml

        # ASH applies these entries itself, so the file is parsed as ASH parses
        # its own configuration: no aliases. An entry list of aliases to one
        # entry whose paths are aliases to one list is read as every entry
        # times every path.
        try:
            document = load_config_yaml(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(str(exc)) from exc
        if not isinstance(document, dict):
            raise ValueError("the document is not a mapping")
        for section in ("vulnerabilities", "misconfigurations", "secrets", "licenses"):
            items = document.get(section)
            if items is None:
                continue
            if not isinstance(items, list):
                # A scalar here raised an uncaught TypeError during config
                # resolution; the file is unparsable, as the caller reports it.
                raise ValueError(f"the {section} section is not a list")
            for item in items:
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                if _expired(item.get("expired_at"), today):
                    continue
                if item.get("purls"):
                    # trivy limits such an entry to the packages its purls name.
                    # A finding's package is not matched here, so applying the
                    # entry would suppress findings trivy reports for other
                    # packages: it is left out, and those findings stay reported.
                    continue
                paths = item.get("paths")
                if paths is None:
                    paths = []
                if not isinstance(paths, list):
                    raise ValueError(f"an entry's paths in {section} is not a list")
                if not all(isinstance(path, str) for path in paths):
                    # A path that is not a string was dropped from the list, so
                    # an entry whose every path was one (`paths: [1]`) read as an
                    # entry with no path limit and applied to every file. trivy
                    # refuses such a file; so does this reader.
                    raise ValueError(
                        f"an entry's paths in {section} holds a value that is not "
                        "a string"
                    )
                found.append((str(item["id"]), tuple(paths)))
        return found
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0].startswith("#"):
            continue
        expiry = next(
            (field[len("exp:") :] for field in fields[1:] if field.startswith("exp:")),
            None,
        )
        if _expired(expiry, today, whole_field=True):
            continue
        found.append((fields[0], ()))
    return found


_PLAIN_EXPIRY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")


def _expired(value: Any, today: date, whole_field: bool = False) -> bool:
    """Whether a trivy ignore entry with this expiry no longer applies on ``today``.

    From the start of the day named, as trivy reads it (the entry is dropped
    once its date is before the time of the scan) and as ASH's own rule reads
    an ``expiration`` (``models/core.expiration_has_passed``). A strict
    less-than before, so an entry still applied on the day itself, which both
    drop it on.

    Raises:
        ValueError: the expiry is not a YYYY-MM-DD date. The file is then
            unreadable, as the caller reports it, and none of its entries is
            applied, so every finding it names is reported. Read as unexpired
            before, such an entry suppressed findings whatever trivy made of a
            date it could not read; ``_entry_expired`` reads a client entry's
            unreadable expiration as expired, the same side.
    """
    # A plain line's ``exp:`` with nothing after it is a field trivy fails to
    # parse, which is not the same as a line with no field (None): it falls
    # through to the date check below. A YAML ``expired_at`` left empty is the
    # zero time trivy reads as no expiry.
    if value is None or (not value and not whole_field):
        return False
    text = str(value)
    try:
        if whole_field:
            # The plain format's ``exp:`` field is parsed whole, as
            # ``time.Parse("2006-01-02", ...)`` parses it: cut at ten
            # characters, ``2099-01-01T00:00`` and ``2099-01-01x`` read as a
            # date that applies, where trivy takes neither as one.
            if _PLAIN_EXPIRY.match(text) is None:
                raise ValueError(text)
        else:
            # A YAML date or timestamp object is its first ten characters.
            text = text[:10]
        return date.fromisoformat(text) <= today
    except ValueError as exc:
        raise ValueError(
            f"an entry's expiry {str(value)!r} is not a YYYY-MM-DD date"
        ) from exc


def matching_exclusion(
    exclusions: Iterable[ClientScannerExclusion],
    *,
    scanner_name: Optional[str],
    relative: str,
    absolute: str,
    rule_id: Optional[str],
    budget: Optional[EvaluationBudget] = None,
) -> Optional[ClientScannerExclusion]:
    """The first of ``exclusions`` that would have kept this finding from its scanner.

    ``budget`` is the suppression pass's ``EvaluationBudget``, handed to each
    entry's ``hides`` so every bounded search of the pass shares one deadline.
    """
    for exclusion in exclusions:
        if exclusion.applies_to(scanner_name) and exclusion.hides(
            relative=relative, absolute=absolute, rule_id=rule_id, budget=budget
        ):
            return exclusion
    return None


#: The CycloneDX property name a marked SBOM component carries.
SBOM_PROPERTY = "ash:clientSuppliedExclusion"


def mark_sbom_components(
    report: Any, exclusions: Iterable[ClientScannerExclusion]
) -> int:
    """Mark each SBOM component a delivered syft exclusion would have dropped.

    A component's files are its ``syft:location:<n>:path`` properties. Each match
    adds a ``SBOM_PROPERTY`` property naming the option and entry, once. Returns
    how many components were marked.
    """
    syft = [item for item in exclusions if item.applies_to("syft")]
    if not syft:
        return 0
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import Property

    marked = 0
    pending = list(getattr(report, "components", None) or [])
    while pending:
        component = pending.pop()
        pending.extend(getattr(component, "components", None) or [])
        properties = list(getattr(component, "properties", None) or [])
        locations = [
            str(prop.value).lstrip("/")
            for prop in properties
            if prop.name
            and prop.name.startswith("syft:location:")
            and prop.name.endswith(":path")
            and prop.value
        ]
        added = False
        for exclusion in syft:
            if not any(glob_excludes(exclusion.pattern, where) for where in locations):
                continue
            value = f"{exclusion.key}: {exclusion.pattern}"
            if any(p.name == SBOM_PROPERTY and p.value == value for p in properties):
                continue
            properties.append(Property(name=SBOM_PROPERTY, value=value))
            added = True
        if added:
            component.properties = properties
            marked += 1
    return marked
