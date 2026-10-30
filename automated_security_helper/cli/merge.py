# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Recombine the shard results of one sharded scan into a single report.

Why this exists
---------------
``ash scan --shard-index k --shard-count n`` splits one scan across n CI
executors by partitioning the *scanner* set (see
:mod:`automated_security_helper.core.sharding` for why scanners and not files).
Each executor writes its own ``ash_aggregated_results.json`` holding the results
of the scanners it owned. Something has to put them back together, and the whole
value of sharding depends on that recombination being trustworthy: a partial
merge that reads as a complete scan is worse than no sharding at all, because a
reviewer cannot tell the difference by looking at it.

The verdict is the sharpest version of this. A shard that happened to own only
syft and grype finds nothing and exits 0. Five such shards mean five green CI
jobs and a repository full of critical findings that nobody was told about.
``ash merge`` therefore owns the real verdict for a sharded run, computed over
the union, and CI must gate on this command rather than on per-shard success.

Why one collapsed SARIF run, unlike workspace mode
--------------------------------------------------
Merging goes through :meth:`SarifReport.merge_sarif_report`, which collapses
everything into ``runs[0]``. That is deliberate, and it is the opposite of the
choice :mod:`automated_security_helper.workspace.aggregation` makes.

Read that module's docstring for the full argument; the short version is that a
SARIF run can declare only one root. Workspace mode has N project roots, so it
must keep one run per project or consumers that ingest SARIF against a single
repository root -- GitHub code scanning above all -- mis-locate or reject the
results. Shards all scan the *same* root, so there is exactly one root to
declare and one collapsed run is the honest shape.

``WorkspaceAggregator`` was considered and rejected for this reason. Using it
here would emit n runs for one repository, each identical in root and differing
only in which scanners contributed, which describes a workspace that does not
exist and would make every consumer's per-run attribution meaningless.

What merge_sarif_report does with a shard's tool components
-----------------------------------------------------------
``merge_sarif_report`` was written to fold one *scanner's* SARIF into ASH's
aggregate, and merging two ASH *aggregates* is a different case: every shard's
driver is ASH itself, and each shard's per-scanner tool components live in
``runs[0].tool.extensions``. It folds both now: each incoming run's driver and
every one of its ``extensions`` joins the aggregate's first run
(``schemas/sarif_schema_model._fold_tool_component``), matched on the
``(name, fullName, organization)`` triple, with a component already present
taking the union of the rules by id. So the rule metadata of every scanner
owned by shards 1..n-1 survives the merge, and a merged result's ``ruleId``
still resolves to its rule's description and help URI. No second pass is
needed here; a merge used to run one and union the same components again.

Deduplication is deliberately absent, here as elsewhere. Two shards never own
the same scanner (:func:`verify_shard_coverage` refuses that), so there is no
legitimate duplicate to collapse, and a merge that quietly dropped
similar-looking findings from different scanners would be hiding real results.

The aggregated suppression pass, and why omitting it broke equivalence
---------------------------------------------------------------------
``AshExecutionEngine`` applies ``apply_suppressions_to_sarif`` to the aggregated
SARIF just before the report phase, because per-scanner passes miss findings
whose paths only become matchable after merge and normalization. This command
originally went from ``merge_sarif_report`` straight to metrics and reports, so
nothing applied suppressions to the cross-shard product: a suppression that only
matched post-merge applied in an unsharded scan and not in a sharded one, and
``ash merge`` exited 2 where ``ash scan`` exited 0 on the same tree.
:func:`apply_aggregated_suppressions` closes that, and ``--ignore-suppressions``
makes the other half of the contract expressible.

That the equivalence was reported as verified end to end before this existed is
the useful part of the story. The verification used a tree with no suppressions
at all, so it could not have failed. A parity property has to be exercised on
input where the two paths could actually disagree, which for suppressions means a
suppression that matches only after the collapse.

Shard provenance, and the field that does not exist yet
-------------------------------------------------------
Coverage is verified from the result files alone rather than from a
``--shard-count`` argument, so that an operator who changes their CI matrix in
one place and not the other gets a loud failure instead of a short merge.

That requires each shard to record what it was asked to run.
``ScanPhase._shard_assignment`` computes exactly that, but as of this commit
nothing persists it: ``AshAggregatedResults`` has no shard field, and the
stamping would have to happen in the scan phase or execution engine.
:func:`read_shard_assignment` therefore accepts provenance from either of the
two places it could plausibly land -- a top-level ``shard`` attribute, if the
model later grows a first-class field, or a ``shard`` key inside ``metadata``,
which works today because ``ReportMetadata`` is declared ``extra="allow"`` and
so round-trips unknown keys through JSON untouched. Being liberal about which
carrier is used costs three lines and means this command stays correct whichever
way the scan side lands it. :func:`stamp_shard_assignment` writes the
``metadata`` form and is what the scan side should call.

A results file with no provenance is refused rather than guessed at. The
alternative -- treating an unstamped file as "probably the only shard" -- would
make ``ash merge`` silently accept a single unsharded scan as a complete merge
of a five-way split.

Why the merged report drops its own shard key
--------------------------------------------
The merged output deliberately does *not* carry a ``shard`` key. It records
``merged_shard_count`` and ``merged_shard_indices`` instead. Copying the base
shard's assignment through would make the merged file look like shard 0 of n, so
a second ``ash merge`` over an output directory would accept it and report a
whole scan as one fifth of itself.

The recorded configuration is the repository's
-----------------------------------------------
Each shard's results carry the configuration its scan resolved, and the merge
builds its reporters from the lowest-indexed shard's copy. That copy was built
from whatever config the shard's scan read, a file inside the scanned tree
included, and it reaches the merge as data in an artifact. So the settings a
config file inside the scanned tree may not choose are not taken from it here
either. :func:`confine_recorded_config` runs ``confine_to_trusted_base``, the
steps ``resolve_config`` runs for such a file (sandbox grants, plugin modules,
reporter destinations and whether the off-host reporters run, scanner config
files), and ``confine_declared_reporter_destinations`` runs once the plugin
modules are loaded. Both run against the operator's trusted base at merge time:
the defaults, ``--config``, and ``--config-overrides``. ``--config`` is itself
confined when it is inside the working directory's tree, as for ``ash report``:
the outermost git checkout around the working directory, or the working
directory itself outside one. A step added to ``confine_to_trusted_base``, or a
row added to those modules' tables, applies here without a change to this one.

Two things differ from a scan, and ``SHARD_RECORDED`` carries both. The warnings
name the shard's results file and give ``ash merge``'s own options as the fix. And
the merge imports ASH's built-in plugins and the modules the operator names, in
``--config`` and ``--config-overrides``, whether or not a shard recorded them; an
``ash_plugin_modules`` entry only a shard names is dropped even when it is an
installed module outside the tree, with one warning naming it: nothing the merge
imports is a shard's choice. So the merge does not need
``drop_untrusted_off_host_plugins``; every class it loads comes from a module the
operator named. ``enabled`` of a reporter that sends findings off the host comes
from the operator alone, in both directions, as in a scan: a shard's ``false`` is
ignored with the warning like its ``true``.

``--config-overrides`` are applied to every shard's recorded configuration as it
is loaded (:func:`apply_operator_overrides`), so the completion gate, the verdict
and the reporters all see them, and they are replayed onto the trusted base, as
in a scan. ``--config`` supplies only the trusted values and does not replace the
recorded configuration: a reporter section the shards did not configure is added
with ``--config-overrides``. Its plugin modules are the exception, as above.

The verdict settings (``fail_on_findings``, ``fail_on_incomplete_scanners``, the
severity thresholds, suppressions, ignore paths and content database bounds)
still come from the shards, since the verdict follows the scan's own
configuration. One verdict covers the merged scan, so shards whose recorded
values differ after the overrides are refused (:func:`verify_verdict_settings_agree`)
rather than decided by the lowest index, and a value ``--config`` sets for one of
them is named in a warning with the override that would apply it
(:func:`warn_on_ignored_operator_verdict_settings`).

The exception is a field a shard recorded as a reference read from the
environment, which its field (``severity_threshold``, ``output_formats``) cannot
hold. The merge does not read the environment again, so that field comes from
``--config-overrides`` or the file ``--config`` (or ``ASH_CONFIG``) names, and a
merge in which any shard's field is supplied by neither is refused once, naming
each field with its reference and the shards and results files that recorded it
(:func:`supply_unread_recorded_fields`). A config file the merge finds in the
working directory supplies nothing.

Known limitations
-----------------
A directory passed to ``--results`` must resolve to exactly one results file.
Pointing it at a parent holding every shard's artifact directory is refused with
a message naming what was found. Merging everything found beneath a directory
was considered and rejected: it makes the set of merged shards depend on
whatever else happens to be in the tree, including a previous merged output, and
the repeatable ``--results`` flag already expresses "these n shards" exactly.

``cyclonedx`` is united across the shards the way a single scan unites its own
SBOMs (syft runs on the source tree and on the converted tree), with
``utils/sbom_merge.py``. Shards are visited in index order. The ``version`` and
``metadata`` are the first SBOM's, the lowest-indexed shard's that has one. A merge
that adds a component, a dependency or a reference gives the merged SBOM a new
``serialNumber``; one that adds nothing keeps the first SBOM's. ``components`` hold
every component of every shard, a repeat listed once and matched on ``bom-ref`` and
``purl`` together or, for a component without a ``bom-ref``, on ``purl``, and
``dependencies`` are united by ``ref``. Two limits carry over. A package that two
shards name with different ``bom-ref`` values is listed twice. And only
``components`` and ``dependencies`` are combined: every other list comes from the
first SBOM, so a later shard's ``vulnerabilities``, ``services``, ``annotations``
and ``compositions`` are not carried. syft writes none of them. With the default
scanner set only syft produces an SBOM, so it lands on exactly one shard and that
SBOM is kept as it is.

``summary_stats.duration`` is the longest shard's duration, not the sum. Shards
run concurrently, so summing would report a wall-clock time several times longer
than the run actually took; the longest shard is the critical path and is the
number an operator comparing sharded against unsharded wants. Total compute
across shards is not recorded.
"""

from __future__ import annotations

import copy
import os
import functools
import hashlib
import json
import logging
import shlex
import typing
from datetime import datetime
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Sized,
    Tuple,
    Type,
)

import typer
import yaml
from pydantic import BaseModel, ValidationError
from rich.text import Text

# `print` shadows the builtin on purpose: this is rich's documented import
# idiom, so every print() below renders markup and respects the console. The
# fix A004 wants is an alias, which would mean rewriting every call in this
# module for no behavior change -- and tests/unit/cli/mcp/test_stdout_jsonrpc_safety.py
# reasons about this exact import form. It is utils/console.py's print, not rich's:
# its console checks each line it writes off a terminal, so none reads as a CI command.
from automated_security_helper.utils.console import print  # noqa: A004

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    off_host_reporter_refused,
    reporter_classes_for_run,
    warn_off_host_section_without_enabled,
)

# Imported at module scope, and not lazily inside the functions that need it,
# because importing this module is what calls AshAggregatedResults.model_rebuild().
# AshAggregatedResults declares ash_config as a forward reference to AshConfig, so
# until that rebuild runs the model has no validator at all and
# model_validate_json raises PydanticUserError. ``ash report`` gets the same
# rebuild by side effect of importing resolve_config; relying on an import made
# for another purpose is what makes this fragile, so the dependency is named here.
from automated_security_helper.config.ash_config import AshConfig, reduced_plugin_name
from automated_security_helper.config.plugin_module_trust import split_plugin_modules
from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
    REPORTER_ENABLED_DEFAULTS,
    confine_declared_reporter_destinations,
    confine_off_host_reporters_to_overrides,
    declared_destination_options,
    declared_enabled_defaults,
)
from automated_security_helper.config.recorded_config import (
    HOW_TO_SUPPLY,
    take_own_values,
    unreadable_references,
    unsupplied_references,
    unsupplied_refusal,
)
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    confine_to_trusted_base,
    resolve_config,
)
from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.untrusted_source import SHARD_RECORDED
from automated_security_helper.core.constants import (
    ASH_EXIT_USAGE_ERROR,
    ASH_WORK_DIR_NAME,
    PYTHON_ONLY_SKIPPED_REASON,
    SHARD_SPLIT_REASON_PREFIX,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    ExportFormat,
    MinSeverity,
    ScannerStatus,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
    ShardCoverageError,
)
from automated_security_helper.core.phases.report_phase import ReportPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.core.sharding import (
    ShardAssignment,
    verify_shard_coverage,
)
from automated_security_helper.core.sharding import shown_shard_text as _shown
from automated_security_helper.core.unified_metrics import (
    populate_metrics_from_unified_source,
    recorded_reason,
    target_counts,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    new_report_id,
    warning_of_dropped_keys,
)
from automated_security_helper.models.asharp_model import (
    ConverterStatusInfo,
    FailedInputInfo,
    InputNotScanned,
    RefusedInputInfo,
    waives_gate,
)
from automated_security_helper.models.core import (
    IgnoreFileExclusions,
    merged_honoring,
)
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.config.plugin_module_trust import config_module_names
from automated_security_helper.plugins.loader import (
    PluginModuleError,
    PluginModuleNamespaceError,
    combined_plugin_load_errors,
    load_plugins,
    plugin_module_fix,
    refuse_plugin_modules_outside_namespace,
)
from automated_security_helper.utils.atomic_write import write_text_atomically
from automated_security_helper.utils.display_text import (
    escape_controls_in,
    path_spellings,
)
from automated_security_helper.utils.error_text import (
    config_environment_values,
    text_without_values,
)
from automated_security_helper.utils.inner_run_outcome import without_run_records
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    NO_MARKUP,
    escape_markup,
    get_logger,
)
from automated_security_helper.utils.output_dir_links import (
    OutputDirLinkRefused,
    refuse_linked_output_dir,
)
from automated_security_helper.utils.report_path_links import ReportPathRefused
from automated_security_helper.utils.sbom_merge import merge_cyclonedx_reports
from automated_security_helper.utils.secret_masking import mask_secrets_in_results
from automated_security_helper.utils.terminal_text import (
    raw_controls_on_one_line,
    raw_controls_shown,
    shown_on_one_line,
)

#: The filename every ASH scan writes its aggregated results to. A ``--results``
#: directory is searched for this name.
RESULTS_FILE_NAME = "ash_aggregated_results.json"

#: Key under ``AshAggregatedResults.metadata`` carrying one shard's assignment.
SHARD_PROVENANCE_KEY = "shard"

#: Keys the merged report carries in place of ``SHARD_PROVENANCE_KEY``.
MERGED_SHARD_COUNT_KEY = "merged_shard_count"
MERGED_SHARD_INDICES_KEY = "merged_shard_indices"

#: Relative locations searched, in order, when ``--results`` names a directory.
#: These mirror the candidates ``ash report`` already probes, so an operator who
#: can point ``ash report`` at a directory can point ``ash merge`` at the same one.
_RESULTS_DIR_CANDIDATES = (
    Path(RESULTS_FILE_NAME),
    Path("ash_output") / RESULTS_FILE_NAME,
    Path(".ash") / "ash_output" / RESULTS_FILE_NAME,
)


#: The two statuses that say a scanner did not run, as opposed to ran and reached a
#: verdict. An unclaimed row carrying only these is reported through
#: ``incomplete_scanners`` and the ``fail_on_incomplete_scanners`` gate rather than
#: refused as a shard-coverage failure -- see :func:`_verify_scanner_union`.
_NEVER_ATTEMPTED_STATUSES = frozenset(
    {ScannerStatus.ERROR.value, ScannerStatus.MISSING.value}
)


def _each_value_once(*groups: Optional[Iterable[str]]) -> list[str]:
    """The groups' values joined, each once, in their first order. A group
    given as one string is one value (``value_tuple``), never its characters."""
    from automated_security_helper.utils.redacted_model import value_tuple

    return list(
        dict.fromkeys(value for group in groups for value in value_tuple(group or ()))
    )


def _normalized(name: str) -> str:
    """Canonical form for comparing scanner names across shards.

    Scanner display names reach the results as ``config.name`` verbatim, so one
    shard can record "Bandit" where another records "bandit". Every comparison in
    this module goes through here because the rest of the CLI already treats
    scanner names case insensitively -- ``ScanPhase`` lowercases both sides of the
    exclusion check, and ``sharding._normalized`` lowercases the partition. A
    case-sensitive comparison here would read one scanner as two and report the
    owning shard's real result alongside another shard's skip marker.
    """
    return name.strip().lower()


# ---------------------------------------------------------------------------
# Shard provenance
# ---------------------------------------------------------------------------


def stamp_shard_assignment(
    results: AshAggregatedResults, assignment: ShardAssignment
) -> None:
    """Record *assignment* on *results* so ``ash merge`` can verify coverage.

    This is what the scan side should call once a shard's results are final.

    Assigns the ``ShardAssignment`` itself, not ``model_dump()``. Dumping first
    was tried and rejected: ``ReportMetadata`` declares ``shard`` as a real field
    and does not enable ``validate_assignment``, so a dict is stored raw and every
    later ``model_dump_json`` emits ``PydanticSerializationUnexpectedValue:
    Expected ShardAssignment``. The JSON comes out correct, but the warning is
    noise on every serialization, and worse, a fixture that stored a dict would
    exercise a shape the scan side never produces -- ``execution_engine`` assigns
    the object.

    Args:
        results: The shard's aggregated results.
        assignment: What this shard was asked to run.
    """
    setattr(results.metadata, SHARD_PROVENANCE_KEY, assignment)


def read_shard_assignment(results: AshAggregatedResults) -> ShardAssignment | None:
    """Return the shard assignment recorded on *results*, or None if absent.

    Two carriers are accepted; see the module docstring for why. A top-level
    ``shard`` attribute wins over the ``metadata`` key, on the grounds that a
    first-class field would be the deliberate later choice and the metadata key
    could linger from an older run.

    Returns None rather than raising so the caller can name the offending file.

    Args:
        results: A single shard's aggregated results.

    Returns:
        The recorded assignment, or None when the file carries no provenance.
    """
    for carrier in (results, results.metadata):
        raw = getattr(carrier, SHARD_PROVENANCE_KEY, None)
        if raw is None:
            continue
        if isinstance(raw, ShardAssignment):
            return raw
        try:
            return ShardAssignment.model_validate(raw)
        except ValidationError:
            # A malformed value is reported as missing provenance rather than
            # crashing with a validation traceback. The caller's message names
            # the file, which is what an operator needs; the shape of the bad
            # value is not.
            #
            # ValidationError rather than Exception: model_validate is the only
            # call in the try, and it raises exactly this for every rejected
            # shape -- dict with a bad field type, empty dict, int, str, list and
            # a bare object were each checked. Anything else escaping this
            # function is a defect worth a traceback rather than a silent None.
            continue
    return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


class ResultsPathError(ShardCoverageError):
    """A ``--results`` value that names no file or directory: a mistyped argument.

    A ShardCoverageError too, so a caller that catches that catches this; the
    CLI tells it apart to exit with the usage-error code rather than 1, which it
    keeps for shards that exist and cannot be merged.
    """


def resolve_results_file(target: str | Path) -> Path:
    """Resolve one ``--results`` value to a single results file.

    A file is used as given. A directory is searched at the well-known relative
    locations first, and only then recursively -- the recursive search must find
    exactly one candidate, because picking one of several would silently drop
    shards. Neither search follows a symlink beneath the directory.

    Args:
        target: A results file, or a directory containing one.

    Returns:
        The path to the results file.

    Raises:
        ResultsPathError: If *target* does not exist, or is neither a file nor a
            directory.
        ShardCoverageError: If *target* is a directory holding no results file or
            more than one.
    """
    path = Path(target)
    if path.is_file():
        return path
    # Shown as the operator typed it, not as the Path object spells it: on
    # Windows a Path writes "\" for every "/" the operator gave, and a trailing
    # separator is dropped on every host, so the refusal named a path the
    # operator never typed.
    if not path.exists():
        raise ResultsPathError(
            f"--results path does not exist: {_shown(target)}. Refusing to merge, "
            f"because skipping an unreadable shard would produce a partial report "
            f"that reads as complete."
        )
    if not path.is_dir():
        raise ResultsPathError(
            f"--results path is neither a file nor a directory: {_shown(target)}."
        )

    # Not through a symlink at any level beneath the directory, here or in the
    # recursive search: one can point anywhere, a file outside the tree or a procfs
    # file that blocks included. A --results path the operator named is still
    # followed.
    for candidate in _RESULTS_DIR_CANDIDATES:
        resolved = path.joinpath(candidate)
        if not _reached_through_a_link(path, candidate) and resolved.is_file():
            return resolved

    # Regular files only: a named pipe by this name (an artifact archive can
    # carry one) was returned, and reading it waited forever. rglob does not
    # descend into a linked directory.
    found = sorted(
        p for p in path.rglob(RESULTS_FILE_NAME) if p.is_file() and not p.is_symlink()
    )
    if not found:
        raise ShardCoverageError(
            f"No {RESULTS_FILE_NAME} found in {_shown(path)}. Checked "
            f"{', '.join(c.as_posix() for c in _RESULTS_DIR_CANDIDATES)} and then "
            f"recursively; symlinks beneath it are not followed. Check that the "
            f"shard's CI job succeeded and uploaded its output directory."
        )
    if len(found) > 1:
        listed = "\n  ".join(_shown(p.as_posix()) for p in found)
        raise ShardCoverageError(
            f"{_shown(path)} contains {len(found)} results files:\n  {listed}\n"
            f"Pass one --results per shard rather than a parent directory. Merging "
            f"everything found beneath a directory would make the merged set depend "
            f"on whatever else is in the tree, including a previous merged report."
        )
    return found[0]


def _reached_through_a_link(base: Path, relative: Path) -> bool:
    """Whether any component of *relative*, taken from *base*, is a symlink."""
    current = base
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def load_shard_results(
    targets: Sequence[str | Path],
) -> List[Tuple[Path, AshAggregatedResults]]:
    """Load every shard's results, in the order given.

    Args:
        targets: The ``--results`` values.

    Returns:
        (path, results) pairs.

    Raises:
        ShardCoverageError: If a path cannot be resolved or parsed. Parse failures
            are reported here rather than skipped, because a shard that produced
            an unreadable file did not contribute its scanners.
    """
    loaded: List[Tuple[Path, AshAggregatedResults]] = []
    for target in targets:
        results_file = resolve_results_file(target)
        try:
            with (
                open(results_file, "r", encoding="utf-8") as handle,
                warning_of_dropped_keys(results_file) as context,
            ):
                loaded.append(
                    (
                        results_file,
                        AshAggregatedResults.model_validate_json(
                            handle.read(), context=context
                        ),
                    )
                )
        except ShardCoverageError:
            raise
        except Exception as exc:
            # from None: the ValidationError's own text quotes the file, and a
            # traceback of this refusal would print it as the cause.
            raise ShardCoverageError(
                f"Could not read shard results from {_shown(results_file)}: "
                f"{_describe_unreadable_shard(exc)}"
            ) from None
    return loaded


#: What a refusal prints in place of a key that is not a field name, beside
#: config_validator's REDACTED (``<value>``) for a value of the file.
_REDACTED_KEY = "<key>"


def _describe_unreadable_shard(exc: Exception) -> str:
    """Why a shard results file could not be read, without repeating any of it.

    A results file holds finding data: snippets, paths, and keys a scanner or a
    configuration chose. pydantic's own text for a ValidationError quotes each
    input as ``input_value='...'``, an error's location names every mapping key
    on its path, and ASH's validators quote the value they refuse ("Use
    YYYY-MM-DD: <value>"). So each error is given as ``Invalid value at '<loc>':
    <message>``, the shape config_validator.format_model_error uses, where:

    - a location part is printed only when it is a field name, alias or model
      name of the results schema, an index as ``[n]``, and ``<key>`` otherwise;
    - every string of the input is replaced in the message by ``<value>``,
      except for invalid JSON, whose message gives a line and column and no
      input;
    - control characters are written as ``\\xNN``.

    A file that is not UTF-8 is described by the offset of the first bad byte;
    the decoder's own text prints the byte.
    """
    if isinstance(exc, UnicodeDecodeError):
        text = f"not UTF-8 at byte offset {exc.start}"
    elif isinstance(exc, ValidationError):
        names = _results_schema_names()
        problems = []
        for error in exc.errors(include_url=False):
            location = ""
            for part in error["loc"]:
                if isinstance(part, int):
                    location += f"[{part}]"
                else:
                    shown = part if part in names else _REDACTED_KEY
                    location += f".{shown}" if location else shown
            message = str(error["msg"])
            if error["type"] != "json_invalid":
                message = _redact_values(message, _string_leaves(error.get("input")))
            problems.append(
                f"Invalid value at '{location or '(top level)'}': {message}"
            )
        text = "; ".join(problems)
    elif isinstance(exc, OSError):
        # The refusal names the shard; the error's own text would name it again,
        # quoted, a Windows path's backslashes doubled.
        text = exc.strerror or type(exc).__name__
    else:
        text = str(exc)
    return _shown(text)


def _shown_lines(message: str) -> str:
    """A whole refusal as it is printed: its own line breaks kept, nothing obeyed.

    Its values are already shown with _shown where merge.py and core/sharding.py
    build it; this is the second guard, for the whole message. A control left raw
    is written as its escape, tab and newline kept, and a line that would begin
    with "::", or holds "##" with an optional name and "[", has that character
    written as ``\\x3a`` or ``\\x23``, which a CI log shows but does not run (a
    bare "##", a Markdown heading's, is no command and is left). Nothing is
    shown again (utils/terminal_text.py's raw_controls_shown): showing each line
    as _shown does doubled the backslash of every escape the sites wrote.
    """
    return raw_controls_shown(message)


def _refusal_text(error: Exception) -> Text:
    """A refusal as ``ash merge`` prints it: red, its values shown once.

    The message is built from shown values (_shown) and shown whole by
    _shown_lines, so it holds no control a terminal acts on. It is printed as
    Text, which reads no markup, rather than through escape_markup: that shows a
    value's controls itself, and run over shown text it doubled the backslash of
    each escape, so a name holding ESC printed as ``x\\\\x1b`` where ``x\\x1b``
    was meant.
    """
    return Text(f"Refusing to merge: {_shown_lines(str(error))}", style="red")


def _invalid_config_text(error: Exception) -> Text:
    """The operator-config refusal as ``ash merge`` prints it, before exit 3.

    The message quotes the operator's path as it is (describe_config_path), and
    the refusal is one line, so the whole message is shown once on one line:
    every control in it, a newline included, is written as its escape
    (``\\x0a``), its backslashes are kept and its CI command forms broken
    (utils/terminal_text.py raw_controls_on_one_line). Printed as Text, which
    reads no markup. Through escape_markup the backslash of each escape was
    doubled, so a name holding ESC printed as ``\\\\x1b`` where ``\\x1b`` was
    meant, and through _shown_lines a newline in the path started a line of its
    own.
    """
    return Text(
        f"Invalid configuration: {raw_controls_on_one_line(str(error))}", style="red"
    )


def _invalid_config_lines(error: Exception) -> Text:
    """A configuration refusal of the merge itself, printed on its own lines.

    For ShardSettingsDisagreeError only: the shards' recorded configurations
    disagreeing on an exit-code setting (verify_verdict_settings_agree) is written
    as a header, one line per setting and the advice, so its line breaks are
    kept. As _refusal_text: the values are already shown where the message is
    built, _shown_lines writes only a raw control as its escape and breaks CI
    command forms, and the Text reads no markup. _invalid_config_text is for every
    other configuration refusal, the --config load's and the ones raised after it:
    each can quote a value the operator typed (a path, a --config-overrides
    entry), and a newline in that value must not start a line of its own.
    """
    return Text(f"Invalid configuration: {_shown_lines(str(error))}", style="red")


@functools.lru_cache(maxsize=1)
def _results_schema_names() -> frozenset[str]:
    """Every field name, alias and model name reachable from AshAggregatedResults.

    The location of a pydantic error mixes these with the keys of mappings the
    file chose (a scanner's name in scanner_results, a key the schema forbids),
    which are data. Measured: 1077 names over 300 models, in about 3 ms.
    """
    names: set[str] = set()
    seen: set[type] = set()

    def visit(annotation: Any) -> None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            if annotation in seen:
                return
            seen.add(annotation)
            names.add(annotation.__name__)
            for name, info in annotation.model_fields.items():
                names.add(name)
                if info.alias:
                    names.add(info.alias)
                if isinstance(info.validation_alias, str):
                    names.add(info.validation_alias)
                visit(info.annotation)
            return
        for argument in typing.get_args(annotation):
            visit(argument)

    visit(AshAggregatedResults)
    return frozenset(names)


def _string_leaves(value: Any) -> List[str]:
    """Every string value in *value*, at any depth: what a validator might quote.

    Mapping keys are left out: a key that reaches a message does so through the
    location, which prints only schema names.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _string_leaves(v)]
    if isinstance(value, (list, tuple)):
        return [s for item in value for s in _string_leaves(item)]
    return []


#: The characters pydantic's str_strip_whitespace trims: Rust's str::trim, the
#: Unicode White_Space set. str.strip() also trims U+001C-001F, so a value starting
#: with one is stored, and quoted by its validator, with it still there. Built with
#: chr() so no escape in this file is rewritten into the character itself.
_PYDANTIC_WHITESPACE = "".join(
    chr(code)
    for code in (
        *range(0x09, 0x0E),
        0x20,
        0x85,
        0xA0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
    )
)


def _redact_values(text: str, values: Iterable[str]) -> str:
    """*text* with every whole occurrence of each value replaced by ``<value>``.

    Through config_validator.redact_values, which a config's refusals use, with
    each value given stripped too, both ways: metadata.generated_at is parsed
    after str.strip(), and a str_strip_whitespace model (a
    content_db_staleness_overrides entry) stores the value with pydantic's own
    strip, and each error quotes what was kept. A copy of it here replaced one
    match at a time: of two values that overlap, part of the second was left in
    the message ("<value>/baz-long"), and a marker already there was marked again.

    Only a ``<value>`` already there is left: a shard's message holds no
    ``<from ${VAR}>`` of a config's, so a value shaped like one is the shard's.
    """
    from automated_security_helper.config.config_validator import (
        REDACTED_MARKERS,
        redact_values,
    )

    from automated_security_helper.utils.redacted_model import value_tuple

    candidates = {
        candidate
        for value in value_tuple(values)
        for candidate in (value, value.strip(), value.strip(_PYDANTIC_WHITESPACE))
    }
    return redact_values(text, candidates, markers=REDACTED_MARKERS, whole_words=True)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _collect_assignments(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
) -> List[Tuple[Path, AshAggregatedResults, ShardAssignment]]:
    """Attach each shard's assignment, refusing any file that carries none.

    Raises:
        ShardCoverageError: If any file has no usable shard provenance.
    """
    if not loaded:
        # Delegated so the "no shards at all" wording lives in one place.
        verify_shard_coverage([])

    unstamped: List[Path] = []
    stamped: List[Tuple[Path, AshAggregatedResults, ShardAssignment]] = []
    for results_file, results in loaded:
        assignment = read_shard_assignment(results)
        if assignment is None:
            unstamped.append(results_file)
        else:
            stamped.append((results_file, results, assignment))

    if unstamped:
        listed = "\n  ".join(_shown(p.as_posix()) for p in unstamped)
        raise ShardCoverageError(
            f"No shard provenance found in {len(unstamped)} results file(s):\n  {listed}\n"
            f"Only a scan run with --shard-index and --shard-count records which "
            f"scanners it owned, and without that record there is no way to tell a "
            f"complete set of shards from a partial one. Refusing to guess: an "
            f"unstamped file could equally be a whole unsharded scan or one shard "
            f"of many."
        )
    return stamped


def _verify_scanner_union(
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> Dict[str, int]:
    """Map each scanner to the position of the shard that owned it.

    ``verify_shard_coverage`` checks the shard *indices* reconstruct one run and
    that no scanner is claimed twice. It cannot see the failure the sharding
    module calls the residual risk: two executors resolving *different* scanner
    sets, so that both partitions are internally valid and the union has a hole.
    That is visible here and nowhere else, by comparing the scanners the shards
    claim against the scanners their results actually mention.

    Args:
        shards: Verified shard results, with assignments.

    Returns:
        Normalized scanner name to index into *shards*.

    Raises:
        ShardCoverageError: If a scanner appears in some shard's results but no
            shard claims it, or if the shard that claims a scanner has no result
            for it.
    """
    owner_by_scanner: Dict[str, int] = {}
    for position, (_, _, assignment) in enumerate(shards):
        for scanner in assignment.assigned_scanners:
            # verify_shard_coverage has already refused any scanner claimed by
            # two shards, so this cannot overwrite a different owner.
            owner_by_scanner[_normalized(scanner)] = position

    seen: Dict[str, Path] = {}
    statuses: Dict[str, set[str]] = {}
    # Whether every row a name carries says the operator deselected the scanner
    # (``excluded``), read beside the status; False as soon as one row does not.
    deselected: Dict[str, bool] = {}
    # Whether some row a name carries was written by the shard split ("assigned to
    # another shard"), which sets the same ``excluded`` flag as a deselection.
    left_to_another_shard: Dict[str, bool] = {}
    for results_file, results, _ in shards:
        for scanner, entry in results.scanner_results.items():
            key = _normalized(scanner)
            seen.setdefault(key, results_file)
            status = getattr(entry, "status", None)
            statuses.setdefault(key, set()).add(str(getattr(status, "value", status)))
            deselected[key] = deselected.get(key, True) and bool(
                getattr(entry, "excluded", False)
            )
            reason = getattr(entry, "skipped_reason", None)
            # The prefix is the scan phase's own spelling (core/constants.py), the one
            # place both writer and reader take it from.
            left_to_another_shard[key] = left_to_another_shard.get(key, False) or (
                isinstance(reason, str) and reason.startswith(SHARD_SPLIT_REASON_PREFIX)
            )

    # An unclaimed row is only an offence when it claims its scanner's outcome is
    # KNOWN, and that narrowing is what keeps this check answering the question it
    # was written for.
    #
    # The harm stated below is that merging "would report them as deliberately
    # skipped rather than never attempted". A row already recording ERROR or MISSING
    # says never-attempted outright, so the merged report does not lose that: the
    # scanner is still listed by `incomplete_scanners`, and the
    # `fail_on_incomplete_scanners` gate is what turns the listing into a non-zero
    # exit code. Refusing the merge instead put a correct finding through a channel
    # no flag reaches, and attributed it to a partitioning disagreement that had not
    # happened.
    #
    # WHAT THE EXEMPTION DOES GIVE UP, stated because the sentence above used to
    # claim it gave up nothing. The refusal applied whatever flags were passed --
    # this function is called unconditionally -- and the channel replacing it does
    # not. `--no-fail-on-incomplete-scanners` removes the exit code as well as the
    # refusal, and then no automated reader sees that a scanner appeared in the
    # results which no shard was ever assigned. That is why the exempted names are
    # emitted at WARNING below instead of being passed over in silence: a disclosure
    # no flag can switch off is what is left once the refusal is gone.
    #
    # Two row shapes reach this, both written by ScanPhase: a scanner whose
    # constructor raised, keyed by its resolved config name, and a plugin module that
    # failed to import, keyed by its dotted module path. Neither can be in
    # `assigned_scanners` -- that list is built from `scanner_instances`, and a module
    # is not a scanner at all -- so before this narrowing a sharded merge refused on
    # both.
    #
    # A DENYLIST OF THE TWO NEVER-ATTEMPTED STATUSES, and not `_completed()`, even
    # though that helper is right next door and looks like the same question. It
    # returns False for a status this version has never heard of, which is fail-CLOSED
    # where it is used (`_verify_shard_contributions` asks "did any owned scanner
    # complete") and fail-OPEN here, where False would mean "exempt". Naming the two
    # statuses keeps an unrecognised one refusing. That asymmetry is invisible from
    # the helper's own definition and only shows up when you ask what the caller does
    # with a False.
    #
    # Every status a row carries has to qualify, across all shards that mention it: a
    # name recorded PASSED by one shard and ERROR by another is the original defect,
    # and taking the ERROR as permission would hide it. A name with no readable status
    # at all is not exempt either.
    #
    # A THIRD ROW SHAPE, written by ScanPhase since the constructor-failure
    # recording moved ahead of the selection filter: a scanner whose constructor
    # raised AND which the operator deselected (excluded, left out of --scanners,
    # disabled in config) is recorded SKIPPED with ``excluded=True`` under its
    # config name, which no shard claims because it never constructed. That row is
    # the operator's own decision, not a partitioning disagreement, and the scan's
    # record of it is right (the skip is real information), so it is exempt here
    # when EVERY row the name carries is SKIPPED and excluded. A SKIPPED row with
    # ``excluded`` False (one shard's selection or config left the scanner out while
    # no shard owns it) stays refused: that is the shape the harm above describes.
    #
    # THE SHARD SPLIT WRITES THE SAME FLAG. A shard records every scanner outside
    # its assignment SKIPPED with ``excluded=True`` too, its reason beginning
    # "assigned to another shard". A name every shard left to "another shard" that
    # no shard's assignment names is a PARTITION HOLE -- the very disagreement this
    # check exists to refuse -- and on shards written before ``candidate_scanners``
    # existed this function is the only detector of it. So the deselection
    # exemption asks the reason as well: a row the split wrote is never a
    # deselection, and such an orphan is refused, naming the hole.
    orphans = set(seen) - set(owner_by_scanner)
    exempted = sorted(
        name
        for name in orphans
        if statuses.get(name)
        and (
            statuses[name] <= _NEVER_ATTEMPTED_STATUSES
            or (
                statuses[name] == {ScannerStatus.SKIPPED.value}
                and deselected.get(name, False)
                and not left_to_another_shard.get(name, False)
            )
        )
    )
    unclaimed = sorted(orphans - set(exempted))
    holes = [name for name in unclaimed if left_to_another_shard.get(name, False)]

    # Ahead of the refusal below so the disclosure is emitted whether or not this
    # call goes on to raise. Both sets are drawn from `orphans`, so a merge can
    # legitimately produce one, the other, or both.
    if exempted:
        exempt_detail = ", ".join(
            f"{name} ({', '.join(sorted(statuses[name]))}, "
            f"seen in {seen[name].as_posix()})"
            for name in exempted
        )
        ASH_LOGGER.warning(
            # Built from the values as the shards recorded them and shown whole,
            # once: shown before they were put in, the sink showed them again and
            # doubled each escape's backslash.
            shown_on_one_line(
                f"{len(exempted)} scanner(s) appear in shard results that no shard "
                f"was assigned: {exempt_detail}. Each row records the scanner as "
                f"never attempted, or as deselected by the operator (SKIPPED, "
                f"excluded), which is why this is not refused as a "
                f"partitioning disagreement and the merge continues. The coverage is "
                f"still short: --fail-on-incomplete-scanners is what turns that into "
                f"a non-zero exit code, and under --no-fail-on-incomplete-scanners "
                f"this line is the only record of it."
            ),
            # Text, not markup: a name such as "[/x]" raised MarkupError, which
            # replaced the merge's verdict with exit 1.
            extra=NO_MARKUP,
        )

    if unclaimed:
        listed = ", ".join(
            f"{_shown(name)} "
            f"({_shown(', '.join(sorted(statuses.get(name) or {'no status'})))}, "
            f"seen in {_shown(seen[name].as_posix())})"
            for name in unclaimed
        )
        raise ShardCoverageError(
            f"These scanners appear in shard results but no shard was assigned "
            f"them: {listed}. No shard ran them, so merging would report them as "
            f"deliberately skipped rather than never attempted. The status of each "
            f"is named above because the cause differs: the executors resolved "
            f"different scanner sets (one missing a plugin module, or a config "
            f"override applied to some jobs and not others), or a "
            f"scanner was excluded by every shard's partition. A scanner that failed "
            f"to construct, or whose plugin module failed to import, is recorded "
            f"ERROR or MISSING instead and is reported through "
            f"--fail-on-incomplete-scanners rather than refused here; one the "
            f"operator deselected is recorded SKIPPED as excluded and is not "
            f"refused either."
            + (
                f" Of these, {_shown(', '.join(holes))} "
                f"{'was' if len(holes) == 1 else 'were'} recorded by every shard "
                f"as assigned to another shard while no shard's assignment names "
                f"{'it' if len(holes) == 1 else 'them'}: a hole in the partition, "
                f"so no shard ran {'it' if len(holes) == 1 else 'them'}."
                if holes
                else ""
            )
        )

    unrecorded_by_owner = sorted(
        name
        for name, position in owner_by_scanner.items()
        if not any(
            _normalized(scanner) == name
            for scanner in shards[position][1].scanner_results
        )
    )
    # Two shapes, split by whether some OTHER shard recorded the name. The
    # refusal here covers only the first: another shard's skip marker is the sole
    # trace, and the merge would adopt it, reporting a scanner that never ran as
    # deliberately skipped. No flag can make that honest, so it is refused
    # whatever was passed.
    #
    # The second shape, an owned scanner that NO shard recorded, belongs to the
    # --fail-on-incomplete-scanners gate, not here: the scanner's whole shard may
    # have run nothing, which is the gate's own case ("completed none of the
    # scanners they owned"), and --no-fail-on-incomplete-scanners is documented as
    # merging such a partial union anyway. An unconditional refusal here fired
    # before that flag could be read, so a single shard whose scanners recorded
    # nothing could no longer be merged to an exit code under the override, which
    # it had always been. _verify_shard_contributions now refuses the shape under
    # the gate, and the disclosure below is what remains of it when the gate is
    # off: emitted whether or not the gated check goes on to raise, because this
    # function cannot see the flag.
    missing_from_owner = [name for name in unrecorded_by_owner if name in seen]
    recorded_nowhere = [name for name in unrecorded_by_owner if name not in seen]
    if recorded_nowhere:
        unrecorded_detail = ", ".join(
            f"{name} (owned by shard {shards[owner_by_scanner[name]][2].shard_index})"
            for name in recorded_nowhere
        )
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"{len(recorded_nowhere)} owned scanner(s) were recorded by no "
                f"shard: {unrecorded_detail}. Nothing says they ran. Under "
                f"--fail-on-incomplete-scanners the merge is refused for them; "
                f"under --no-fail-on-incomplete-scanners the merged report leaves "
                f"them out, and this line is the only record of it."
            ),
            extra=NO_MARKUP,
        )
    if missing_from_owner:
        details = ", ".join(
            f"{_shown(name)} (owned by shard "
            f"{shards[owner_by_scanner[name]][2].shard_index})"
            for name in missing_from_owner
        )
        raise ShardCoverageError(
            f"The shard that owned these scanners recorded no result for them: "
            f"{details}. Another shard's skip marker is the only trace left, and "
            f"adopting it would report a scanner that never ran as deliberately "
            f"skipped. Check whether that shard's scan phase completed."
        )

    return owner_by_scanner


def _completed(entry: Any) -> bool:
    """Whether one ``scanner_results`` entry represents a scanner whose outcome is known.

    PASSED, FAILED and SKIPPED are the three that qualify -- SKIPPED because it is how
    a run-wide exclusion or another shard's ownership is recorded, so the scanner was
    never supposed to run here. Everything else does not, including a status this
    version has never heard of.

    Membership of the *complete* set, not absence from the incomplete one, and that
    matters most here of all the readers. ``ash merge`` consumes results files written
    by whatever ASH produced each shard, so a fan-out whose runners are mid-upgrade can
    hand this an unfamiliar status string. Asking "is it one of the two bad ones"
    answers no for such a status and merges the shard as complete, putting scanners
    whose outcome nobody knows inside a report that reads as a whole scan.

    The status set is imported from ``run_ash_scan`` rather than re-listed, so this and
    ``ash scan``'s gate cannot drift apart. Imported inside the function for the same
    reason :func:`_merged_exit_code` imports from there lazily: ``run_ash_scan`` pulls
    in ``run_ash_container`` at module scope, and there is no reason for a command that
    does not scan to carry that import graph. There is no cycle between the two modules
    -- ``run_ash_scan`` does not import this one -- so the laziness is about cost, not
    about breaking a loop.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        _COMPLETE_SCANNER_STATUSES,
    )

    status = getattr(entry, "status", None)
    status_value = getattr(status, "value", status)
    return status_value in _COMPLETE_SCANNER_STATUSES


def _ran_partially(results: AshAggregatedResults, name: str) -> bool:
    """Whether the shard's recorded counts show the scanner ran and audited some targets.

    The ERROR arm of shard verification, and only the ERROR arm: the recorded
    status must be ERROR, compared by value the way ``_completed`` compares it.
    A MISSING entry, or a status this version does not know (a shard from
    another ASH version), with partial counts beside it is no evidence that the
    scanner ran, so it stays refused. ``_completed`` reads the status alone,
    and an ERROR status alone cannot say whether its scanner ever started. The
    recorded target counts can: a scanner that attempted targets and failed only
    some of them ran, audited the rest, and graded ERROR over the loss, so its
    shard contributed real findings and refusing it as having run nothing would
    discard them. The shortfall is not forgiven -- ``incomplete_scanners`` on the
    merged product still names it and the exit gate still exits 1.

    False for everything else, so the refusal keeps its reach: an ERROR entry
    with no counts (the scanner does not track targets, or never got far enough
    to record any) and one whose every attempted target failed are both
    indistinguishable from a scanner that never ran, and a count outside
    ``0 < failed < attempted`` makes no partial-coverage claim. *name* is a
    normalized scanner name; the recorded spelling is looked up the way
    :func:`_skipped_reason` does, because ``target_counts`` reads
    ``additional_reports`` under the recorded key.
    """
    for recorded, entry in (results.scanner_results or {}).items():
        if _normalized(recorded) == name:
            status = getattr(entry, "status", None)
            if getattr(status, "value", status) != ScannerStatus.ERROR.value:
                return False
            attempted, failed = target_counts(results, recorded)
            return attempted is not None and 0 < failed < attempted
    return False


def _report_scanners_no_shard_selected(
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Name the scanners assigned to a shard, intended by none of them, and asked for.

    A disclosure rather than a refusal. Such a scanner ran on no shard, and the
    merged report presents it as SKIPPED -- which ``_completed`` reads as a known
    outcome, so nothing above objects. Two causes produce that state: a scanner
    every job's selection leaves out (``--scanners``, ``--exclude-scanners``,
    ``--python-only`` or its own ``enabled`` flag), which is the operator's choice,
    and a scanner one job's selection dropped while another's kept it, which is a
    coverage hole no other check can see.

    ``intended_scanners`` tells the two apart: each shard records what its
    selection asks for over every candidate, not only over the scanners it owns.
    A scanner some shard asked for and its owner did not select is the hole, and
    is named at WARNING. A scanner no shard asked for is the operator's choice and
    gets a VERBOSE line only, so a merge of shards run with the same
    ``--scanners`` does not name every scanner outside the list.

    Shards written before ``intended_scanners`` existed cannot be told apart, so
    when any shard lacks it every unselected scanner is named at WARNING, since
    the merged report says SKIPPED either way. Silent when no shard
    recorded a selection, which is every results file written before
    ``selected_scanners`` existed. Inferring a hole from that absence would name
    every scanner on every merge of an older fan-out's artifacts. For the same
    reason a shard that recorded no selection beside shards that did is read
    from its own rows: an assigned scanner it recorded as anything but SKIPPED
    was intended, since it ran, and naming it as intended by no shard would call
    a scanner that ran SKIPPED; one it recorded SKIPPED was left out, by its own
    selection or by a config, and is named as it was before the field existed,
    because the shard's assignment covers scanners it never meant to run
    (``ShardAssignment``: ``--scanners bandit`` leaves grype assigned and
    SKIPPED), so reading the whole assignment as intended hid a scanner one job
    excluded and no job ran.

    A scanner its owning shard recorded as left out by ``--python-only`` is not in
    the warning when every shard ran with that flag. The flag is a selection too, so
    a sharded ``--python-only`` scan leaves every non-Python scanner selected by no
    shard, and naming each with advice about ``--scanners`` and
    ``--exclude-scanners`` points at a cause nobody had. Its merged row says why it
    was skipped, so it is named at INFO with the flag instead, unless a shard's
    ``intended_scanners`` asked for it: then a job wanted it run and none ran it,
    which is a hole whatever its owner's skip reason says. When the shards
    disagree on the flag (``ShardAssignment.python_only``), or a shard did not
    record it, such a scanner stays in the warning: one job left it out and no job
    ran it, which is the hole the warning is for. Either warning then says what
    the shards recorded: which ran with the flag and which did not; which recorded
    running without it and which recorded nothing; or that none recorded it.

    The names are the shards' own, so each line is built from them as recorded
    and shown whole by shown_on_one_line, as text: a newline in a name cannot
    start a line, and the sink writes the shown line as it is. A name shown before
    it was put in would be shown again there, each escape's backslash doubled.

    Args:
        shards: Verified shard results, with assignments.
    """
    if not any(assignment.selected_scanners is not None for _, _, assignment in shards):
        return

    # _normalized here takes one name, unlike sharding._normalized which takes an
    # iterable. Two functions, one name, different arities.
    assigned: dict[str, int] = {}
    owner_results: dict[str, AshAggregatedResults] = {}
    selected: set[str] = set()
    for _, results, assignment in shards:
        for scanner in assignment.assigned_scanners:
            assigned[_normalized(scanner)] = assignment.shard_index
            owner_results[_normalized(scanner)] = results
        if assignment.selected_scanners is None:
            # Written before the field existed, so it says nothing about what the
            # shard left out, and its row for each scanner it owned says what
            # became of it: a scanner that ran (any status but SKIPPED, a missing
            # row included, which the contribution check names) was intended; a
            # SKIPPED one was left out by that shard's own selection or config.
            # Reading the whole assignment as intended hid the second kind, since
            # an assignment covers scanners the shard never meant to run; reading
            # it as an empty selection named the first kind as intended by no
            # shard and said they show SKIPPED when they ran.
            for scanner in assignment.assigned_scanners:
                name = _normalized(scanner)
                if _recorded_status(results, name) != ScannerStatus.SKIPPED.value:
                    selected.add(name)
            continue
        for scanner in assignment.selected_scanners:
            selected.add(_normalized(scanner))

    unselected = sorted(set(assigned) - selected)
    flags = {
        assignment.shard_index: assignment.python_only for _, _, assignment in shards
    }
    every_shard_python_only = all(flag is True for flag in flags.values())
    left_out_by_python_only = [
        name
        for name in unselected
        if _skipped_reason(owner_results[name], name) == PYTHON_ONLY_SKIPPED_REASON
    ]
    # What each shard's selection asked for, over every candidate; None when a
    # shard predates intended_scanners and the two causes cannot be told apart.
    asked_for: Optional[dict[str, list[int]]] = None
    if all(assignment.intended_scanners is not None for _, _, assignment in shards):
        asked_for = {}
        for _, _, assignment in shards:
            for scanner in assignment.intended_scanners or []:
                asked_for.setdefault(_normalized(scanner), []).append(
                    assignment.shard_index
                )
    python_only = [
        name
        for name in left_out_by_python_only
        if every_shard_python_only and (asked_for is None or name not in asked_for)
    ]
    if python_only:
        ASH_LOGGER.info(
            shown_on_one_line(
                f"{len(python_only)} scanner(s) were left out by --python-only on "
                f"the shard that owned them: {', '.join(python_only)}. The merged "
                f"report shows them SKIPPED with that reason."
            ),
            extra=NO_MARKUP,
        )
    unselected = [name for name in unselected if name not in python_only]
    if not unselected:
        return

    def _python_only_disagreement(named: Sequence[str]) -> str:
        """The sentence naming which shards ran --python-only, for *named*."""
        ran_nowhere = [name for name in named if name in left_out_by_python_only]
        if not ran_nowhere or every_shard_python_only:
            return ""
        with_flag = sorted(index for index, flag in flags.items() if flag is True)
        without = sorted(index for index, flag in flags.items() if flag is not True)
        if with_flag:
            return (
                f" The shards disagree on --python-only: shard(s) "
                f"{', '.join(map(str, with_flag))} ran with it and shard(s) "
                f"{', '.join(map(str, without))} did not or did not record it, so "
                f"{', '.join(ran_nowhere)} ran nowhere."
            )
        if all(flag is None for flag in flags.values()):
            # Written by a version that predates the record, or by hand: no shard
            # says it ran with the flag, so there is no disagreement to name, only
            # the scanners its reason left out.
            return (
                f" No shard recorded whether it ran with --python-only, and the "
                f"shards that own {', '.join(ran_nowhere)} recorded them left out "
                f"by it."
            )
        # No shard recorded True, but at least one recorded False: name what
        # each shard recorded, against the reason the owners recorded.
        recorded_false = sorted(index for index, flag in flags.items() if flag is False)
        recorded_none = sorted(index for index, flag in flags.items() if flag is None)
        nothing = (
            f" and shard(s) {', '.join(map(str, recorded_none))} recorded nothing"
            if recorded_none
            else ""
        )
        return (
            f" Shard(s) {', '.join(map(str, recorded_false))} recorded running "
            f"without --python-only{nothing}, but the shards that own "
            f"{', '.join(ran_nowhere)} recorded them left out by it, so they ran "
            f"nowhere."
        )

    if asked_for is not None:
        holes = [name for name in unselected if name in asked_for]
        not_asked = [name for name in unselected if name not in asked_for]
        if not_asked:
            ASH_LOGGER.verbose(
                shown_on_one_line(
                    f"{len(not_asked)} scanner(s) were selected by no shard's "
                    f"--scanners, --exclude-scanners or config, and the merged "
                    f"report shows them SKIPPED: {', '.join(not_asked)}"
                ),
                extra=NO_MARKUP,
            )
        if not holes:
            return
        detail = ", ".join(
            f"{name} (assigned to shard {assigned[name]}, which did not select it; "
            f"asked for by shard "
            f"{', '.join(str(index) for index in sorted(asked_for[name]))})"
            for name in holes
        )
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"{len(holes)} scanner(s) ran on no shard although a shard's "
                f"selection asked for them: {detail}. The jobs of the matrix were "
                f"given different --scanners, --exclude-scanners or config, so the "
                f"merged report shows them SKIPPED and the scan did not run them."
                f"{_python_only_disagreement(holes)}"
            ),
            extra=NO_MARKUP,
        )
        return

    detail = ", ".join(
        f"{name} (assigned to shard {assigned[name]})" for name in unselected
    )
    disagreement = _python_only_disagreement(unselected)
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"{len(unselected)} scanner(s) were assigned to a shard but no shard "
            f"intended to run them: {detail}. The merged report shows them "
            f"SKIPPED, which is correct if a config disables them everywhere and "
            f"misleading if one job's --scanners or --exclude-scanners value "
            f"differed from the others' -- nothing in the shard results can tell "
            f"those apart. Check that every job in the matrix was given the same "
            f"scanner selection.{disagreement}"
        ),
        extra=NO_MARKUP,
    )


def _recorded_status(results: AshAggregatedResults, name: str) -> str | None:
    """The status value *results* recorded for the scanner *name* normalizes to.

    None when no row names it. Read from ``scanner_results`` under the recorded
    key, as :func:`_ran_partially` reads it, so a row recorded under another
    spelling of the name is still found.
    """
    for recorded, entry in (results.scanner_results or {}).items():
        if _normalized(recorded) == name:
            status = getattr(entry, "status", None)
            return getattr(status, "value", status)
    return None


def _skipped_reason(results: AshAggregatedResults, name: str) -> str | None:
    """The ``skipped_reason`` *results* recorded for the scanner *name* normalizes to."""
    for recorded in results.scanner_results or {}:
        if _normalized(recorded) == name:
            return recorded_reason(results, recorded, "skipped_reason")
    return recorded_reason(results, name, "skipped_reason")


def _verify_shard_contributions(
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Refuse a merge where a shard owned scanners but completed none of them.

    The distributed shape of the false-green exit code, and the one thing the
    checks above cannot see. ``verify_shard_coverage`` reads shard *indices*;
    :func:`_verify_scanner_union` reads which scanner *names* appear. Neither
    reads a status. So a shard whose every scanner came back MISSING satisfies
    both and merges into a report that reads as a complete scan of the whole tree,
    a fraction of which never ran -- and because that fraction produced no
    findings, the merged verdict is the same 0 a genuinely clean scan produces.

    Also names the case a status check structurally cannot: an owned scanner
    with no entry at all, where there is no status to inspect. On a shard that
    completed none of its scanners it is listed as ``(no result recorded)``
    beside the statuses. On a shard that did complete some, the scanners it owns
    but never recorded are refused separately: nothing else reads them, so they
    would drop out of the merged report and out of the completeness gate with
    nothing saying they were ever assigned. :func:`_verify_scanner_union` handles
    the one shape this gate must not: an owned scanner that some *other* shard
    recorded, usually as a skip marker, is refused there whatever the flag,
    because merging would adopt that marker.

    A shard that owns nothing is not an offender. A shard count above the scanner
    count leaves surplus shards with an empty assignment, which
    :mod:`automated_security_helper.core.sharding` calls wasteful rather than
    wrong; reading an empty assignment as a failure would turn an over-large
    shard count into a pipeline that cannot merge at all.

    Gated by the caller rather than unconditional, unlike every other refusal in
    this module. Those all describe a set of shards that cannot reconstruct one
    scan whatever the environment. This one describes an environment: four of the
    ten default scanners are MISSING on a machine without cdk-nag, cfn-nag, grype
    and syft installed, and refusing by default would break merges that have
    nothing wrong with them.

    Args:
        shards: Verified shard results, with assignments, in index order.

    Raises:
        ShardCoverageError: If any shard that owned at least one scanner completed
            none of them.
    """
    from automated_security_helper.utils.content_db_staleness import (
        scanners_in_error_for_a_stale_database,
    )

    offenders: List[str] = []
    unrecorded: List[str] = []
    for _, results, assignment in shards:
        owned = [_normalized(name) for name in assignment.assigned_scanners]
        if not owned:
            continue

        entries = {
            _normalized(name): entry for name, entry in results.scanner_results.items()
        }
        absent = [name for name in owned if name not in entries]
        # A scanner recorded ERROR because its clean result came from a database the
        # policy rejects ran, and the merged scan exits 1 on that database. Counted
        # as completed here, as it was when that result was recorded PASSED, so the
        # shard is merged and the stale database is reported rather than the shard
        # refused as having run nothing.
        ran_against_a_stale_database = {
            _normalized(name)
            for name in scanners_in_error_for_a_stale_database(results)
        }
        if any(
            name in entries
            and (
                _completed(entries[name])
                or name in ran_against_a_stale_database
                # An ERROR scanner whose counts show a partial audit ran; see
                # _ran_partially. Checked last because it reads
                # additional_reports, which the two status reads do not.
                or _ran_partially(results, name)
            )
            for name in owned
        ):
            # The shard ran something, so it is not listed below; what it owns
            # and never recorded is still refused, on its own line.
            if absent:
                unrecorded.append(
                    f"shard {assignment.shard_index} of {assignment.shard_count}: "
                    f"{', '.join(_shown(name) for name in absent)}"
                )
            continue

        detail = []
        for name in owned:
            entry = entries.get(name)
            if entry is None:
                detail.append(f"{_shown(name)} (no result recorded)")
            else:
                status = getattr(entry, "status", None)
                detail.append(
                    f"{_shown(name)} ({_shown(getattr(status, 'value', status))})"
                )
        offenders.append(
            f"shard {assignment.shard_index} of {assignment.shard_count}: "
            f"{', '.join(detail)}"
        )

    if offenders:
        listed = "\n  ".join(offenders)
        raise ShardCoverageError(
            f"These shards completed none of the scanners they owned:\n  {listed}\n"
            f"Their scanners contributed no findings because they did not run, not "
            f"because there was nothing to find, so merging would report a partial "
            f"scan as a whole one. Check whether those CI jobs had the scanners' "
            f"tools available. Pass --no-fail-on-incomplete-scanners to merge anyway."
        )
    if unrecorded:
        listed = "\n  ".join(unrecorded)
        raise ShardCoverageError(
            f"These shards owned scanners they recorded no result for:\n  {listed}\n"
            f"Nothing says those scanners ran, so merging would leave them out of "
            f"the report and out of the completeness gate, with nothing saying "
            f"they were ever assigned. Check whether that shard's scan phase "
            f"completed. Pass --no-fail-on-incomplete-scanners to merge anyway."
        )


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------


def _merge_timing(
    base: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Set the merged run's start, end and duration across every shard.

    ``populate_metrics_from_unified_source`` recomputes every count but preserves
    these three, so they are set before it runs. Duration is the longest shard
    rather than the sum; see the module docstring.
    """
    starts = [
        shard.metadata.summary_stats.start
        for _, shard, _ in shards
        if shard.metadata.summary_stats.start
    ]
    ends = [
        shard.metadata.summary_stats.end
        for _, shard, _ in shards
        if shard.metadata.summary_stats.end
    ]
    durations = [shard.metadata.summary_stats.duration or 0.0 for _, shard, _ in shards]

    # Compared as instants where every value parses as ISO-8601, as text
    # otherwise. Every writer emits ISO-8601, but not one spelling of it: a
    # datetime whose microsecond is zero is written without the fraction, and
    # "10:00:00Z" sorts after "10:00:00.5Z" as text while it is the earlier
    # instant. Mixed types would not compare, so each list is filtered to one kind.
    # The parse (_parse_instant) accepts those two spellings on Python 3.10 too,
    # whose fromisoformat refuses them, so the fallback is not the rule there.
    if starts and all(isinstance(value, str) for value in starts):
        base.metadata.summary_stats.start = min(starts, key=_instant_key(starts))
    if ends and all(isinstance(value, str) for value in ends):
        base.metadata.summary_stats.end = max(ends, key=_instant_key(ends))
    if durations:
        base.metadata.summary_stats.duration = max(durations)


def _instant_key(values: Sequence[str]) -> Any:
    """A ``min``/``max`` key that orders *values* as instants when it can.

    Every value has to parse, and the parsed instants have to be all aware or
    all naive, for the chronological order to be defined; otherwise the key is
    the text itself, which is the order the merge used before.
    """
    parsed = []
    for value in values:
        try:
            parsed.append(_parse_instant(value))
        except ValueError:
            return lambda text: text
    aware = {instant.tzinfo is not None for instant in parsed}
    if len(aware) != 1:
        return lambda text: text
    return _parse_instant


def _parse_instant(value: str) -> datetime:
    """``datetime.fromisoformat`` over every spelling the writers emit, on 3.10 too.

    Python 3.10's parser rejects a ``Z`` suffix and a fraction that is not three
    or six digits; 3.11 accepts both. Every value this module compares comes from
    a shard's ``summary_stats``, written by whatever ASH produced it, so the two
    shapes are normalized before parsing (``Z`` to ``+00:00``, the fraction
    padded to six digits) and the recorded text is never changed. A value that
    still does not parse raises ``ValueError``, as before, and the caller falls
    back to text order.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dot = text.rfind(".")
    if dot != -1:
        end = dot + 1
        while end < len(text) and text[end].isdigit():
            end += 1
        digits = text[dot + 1 : end]
        if digits:
            text = f"{text[:dot]}.{(digits + '000000')[:6]}{text[end:]}"
    return datetime.fromisoformat(text)


def _refuse_shards_without_a_config(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
) -> None:
    """Refuse a shard whose results record no scan configuration.

    The merged verdict, the aggregated suppression pass and the report settings
    are read from the configuration the shards scanned under. A shard with none
    is not merged under ASH's defaults in its place.

    Raises:
        ShardCoverageError: Naming each shard that records no configuration.
    """
    missing = [
        Path(path).as_posix()
        for path, results in loaded
        if not isinstance(results.ash_config, AshConfig)
    ]
    if missing:
        raise ShardCoverageError(
            f'Shard results record no scan configuration ("ash_config" is null): '
            f"{', '.join(missing)}. The merged verdict, suppressions and report "
            "settings come from the configuration the shards scanned under, so a "
            "shard without one cannot be merged. Merge the results files the "
            "shards wrote, unedited."
        )


def merge_shard_results(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
    require_scanner_completion: bool = False,
) -> AshAggregatedResults:
    """Merge every shard's results into one report covering the whole scan.

    Coverage is verified before anything is merged, so a partial or duplicated
    set of shards fails without leaving a half-written report behind.

    Does not mutate its inputs; the base is a deep copy of the lowest-indexed
    shard. That shard supplies the report's identity -- name, description,
    ``ash_config`` -- because those are properties of the scan rather than of the
    shard, and taking them from the *lowest index* rather than from the first
    ``--results`` argument makes the merged report independent of the order the
    operator listed the shards in. ``converter_results`` rows are combined across
    shards instead; see :func:`_merge_converter_rows`. So is
    ``metadata.plugin_load_errors``, every shard's modules that failed to import
    (``plugins.loader.combined_plugin_load_errors``). The ``report_id`` is the
    exception: see :func:`_union_report_id`.

    Args:
        loaded: (path, results) pairs, in any order.
        require_scanner_completion: When True, also refuse a set where some shard
            owned scanners and completed none of them. Off by default; see
            :func:`_verify_shard_contributions` for why this one refusal is opted
            into while the rest are unconditional.

    Returns:
        One merged ``AshAggregatedResults`` with recomputed statistics.

    Raises:
        ShardCoverageError: If the shards do not reconstruct exactly one whole
            scan.
    """
    _refuse_shards_without_a_config(loaded)
    shards = _collect_assignments(loaded)
    verify_shard_coverage([assignment for _, _, assignment in shards])

    # Sorted by shard index, not by argument order, so the merged report is
    # byte-identical whichever order the shards were passed in. Two invocations
    # that disagree only in --results order producing different reports would
    # make the output impossible to diff across CI runs.
    shards.sort(key=lambda entry: entry[2].shard_index)
    owner_by_scanner = _verify_scanner_union(shards)
    _report_scanners_no_shard_selected(shards)
    if require_scanner_completion:
        _verify_shard_contributions(shards)

    merged = shards[0][1].model_copy(deep=True)
    # Without each shard's records about its own run: its completion marker, a
    # refusal and the reports it wrote describe that run, not this merge. See
    # utils/inner_run_outcome.py.
    merged.validation_checkpoints = without_run_records(merged.validation_checkpoints)

    # Every shard's row for each converter, gathered first and merged once below.
    # Converters are not sharded: every shard converts the whole tree, so the
    # rows normally agree. They are still each shard's own record, and one
    # shard's runner can fail where another's succeeded -- nbconvert timing out,
    # a tool missing -- so the rows are combined rather than the lowest-indexed
    # one kept. Folding them two at a time meant the joined text of a partial
    # union was read back as its parts on the next fold, which broke a message
    # that itself held the join text; one pass over whole messages never splits.
    # Shards are visited in index order, so the result does not depend on the
    # order they were passed in.
    converter_rows: Dict[str, List[ConverterStatusInfo]] = {
        name: [row] for name, row in shards[0][1].converter_results.items()
    }

    for _, shard, _ in shards[1:]:
        if merged.sarif is None:
            merged.sarif = shard.sarif.model_copy(deep=True) if shard.sarif else None
        elif shard.sarif is not None:
            # Folds the shard's driver and every per-scanner extension too; see
            # the module docstring.
            merged.sarif.merge_sarif_report(shard.sarif)

        # Every shard read the same config, so each recorded the same config
        # warnings; those are kept once. Other checkpoints are per shard.
        merged.validation_checkpoints.extend(
            checkpoint
            for checkpoint in without_run_records(shard.validation_checkpoints)
            if not (
                checkpoint.get("type") == "config_warning"
                and checkpoint in merged.validation_checkpoints
            )
        )
        merged.used_suppressions.update(shard.used_suppressions)

        for name, converter_result in shard.converter_results.items():
            converter_rows.setdefault(name, []).append(converter_result)

        # additional_reports is not gathered here: _adopt_owning_shard_results below
        # rebuilds the merged set from every shard, as copies, so a copy made here
        # was made again there (twice per report, three times for the base shard's).

        # The shards' SBOMs are united in shard order by the rule a single scan
        # uses for its own (utils/sbom_merge.py). A shard whose SBOM is None adds
        # nothing, and the result is a copy rather than either argument, so the
        # merged report shares no object with the shard it came from. Only
        # components and dependencies are combined; a later shard's other lists
        # (vulnerabilities, services, annotations, compositions) are not carried,
        # and syft writes none of them.
        merged.cyclonedx = merge_cyclonedx_reports(merged.cyclonedx, shard.cyclonedx)

    # One pass per converter over every shard's row; a converter one shard alone
    # recorded keeps that shard's row, as a copy.
    for name, rows in converter_rows.items():
        merged.converter_results[name] = (
            rows[0].model_copy(deep=True)
            if len(rows) == 1
            else _merge_converter_rows(rows)
        )

    _adopt_owning_shard_results(merged, shards, owner_by_scanner)
    _merge_scan_set_records(merged, shards)
    # Every shard's, not the base shard's: each shard imports the plugin modules
    # itself, and the completeness gate reads a module missing from this record
    # as one that loaded.
    merged.metadata.plugin_load_errors = combined_plugin_load_errors(
        shard.metadata.plugin_load_errors for _, shard, _ in shards
    )
    _merge_timing(merged, shards)
    _record_merge_provenance(merged, shards)
    merged.metadata.report_id = _union_report_id(shards)
    _merge_scan_markers(merged, shards)

    # Each shard was masked against its own secret findings only, and shards split
    # by scanner, so a secret one shard's scanner reports can sit in another
    # shard's snippets. The merged set is masked against all of them before
    # anything is written; see utils/secret_masking.py. By location from the
    # findings themselves; by value from the shapes every shard recorded, since
    # no shard holds the values any more once it has masked them.
    mask_secrets_in_results(
        merged,
        shapes=[shape for _, shard, _ in shards for shape in shard.secret_value_shapes],
    )

    # Recomputes summary_stats and per-scanner counts from the merged SARIF, the
    # same call the execution engine makes before the report phase. Without it
    # every count would still be the base shard's, so a merged report would show
    # the union's findings under one shard's totals.
    return populate_metrics_from_unified_source(aggregated_results=merged)


def _copied(value: Any) -> Any:
    """A deep copy of a shard's entry, a model or a plain mapping alike.

    ``scanner_results`` entries are models; ``additional_reports`` values are
    whatever a plugin wrote, dictionaries as a rule. The merged report holds
    copies of both so that masking and later merges change nothing the caller
    loaded.
    """
    if hasattr(value, "model_copy"):
        return value.model_copy(deep=True)
    return copy.deepcopy(value)


def _merge_scan_set_records(
    merged: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Set the merged scan-set records in ``metadata`` from every shard's.

    Each shard builds ASH's scan set itself and records what it left out:
    ``inputs_not_scanned`` (the links leaving the scanned tree) and
    ``ignore_file_exclusions``. Shards normally agree, since they scan one tree, but
    one that ran on a different checkout or with ``--no-honor-ignore-files`` does
    not, and its scan-set readers did not scan what it left out. So the merged
    report records what any shard left out, in shard order:

    * ``inputs_not_scanned``: every shard's rows, each (path, reason) once, first
      record kept; None when no shard recorded one.
    * ``ignore_file_exclusions``: ``honored`` only when every shard honored the
      ignore files (as a workspace's merged record says); for each ignore file the
      most any shard says it removed; ``excluded_file_count`` the sum of those, or
      the largest shard count when that is more (a shard that did not honor the
      ignore files can count files the caller's ignore files removed without
      naming them); ``output_dir_file_count`` the largest; and, when some shards
      honored the ignore files and some did not, ``honored_scan_count`` and
      ``scan_count``, so the summaries say that instead of either one-scan
      sentence. None when no shard recorded one.

    Shards are visited in index order, so the result does not depend on the order
    they were passed in. No shard is modified.
    """
    rows: Dict[Tuple[str, str], InputNotScanned] = {}
    for _, shard, _ in shards:
        for row in shard.metadata.inputs_not_scanned or []:
            rows.setdefault((row.path, row.reason), row)
    merged.metadata.inputs_not_scanned = (
        [row.model_copy() for row in rows.values()] if rows else None
    )

    records = [
        shard.metadata.ignore_file_exclusions
        for _, shard, _ in shards
        if shard.metadata.ignore_file_exclusions is not None
    ]
    if not records:
        merged.metadata.ignore_file_exclusions = None
        return
    by_ignore_file: Dict[str, int] = {}
    for record in records:
        for path, count in record.by_ignore_file.items():
            by_ignore_file[path] = max(by_ignore_file.get(path, 0), count)
    merged.metadata.ignore_file_exclusions = IgnoreFileExclusions(
        excluded_file_count=max(
            sum(by_ignore_file.values()),
            max(record.excluded_file_count for record in records),
        ),
        by_ignore_file=by_ignore_file,
        output_dir_file_count=max(record.output_dir_file_count for record in records),
        # honored, and the scan counts when the shards disagree.
        **merged_honoring(records),
    )


#: Joins the distinct failures, and the distinct dependency reasons, of one
#: converter's merged row, for display. Never read back: each shard's message
#: is kept whole, so a message that itself holds this text survives.
_FAILURE_JOIN = "; "


def _merge_converter_rows(rows: Sequence[ConverterStatusInfo]) -> ConverterStatusInfo:
    """One converter's row for the union of every shard's rows, merged in one pass.

    Combined so that the completeness gate (``run_ash_scan.incomplete_converters``)
    sees in the union whatever it would have seen in any shard:

    * ``failure``: every distinct message, in shard order, joined by ``; `` for
      display. Each shard's text is kept whole. Folding two rows at a time
      meant reading a partial union's join back as its parts before the next
      shard's text was added, so a message that itself held ``; `` (a
      CalledProcessError's text does) was broken into fragments, a fragment
      shared with another shard's message collapsed into it, and a third
      shard's identical text was still appended again when the split did not
      restore the original.
    * ``failed_inputs`` and ``refused_inputs``: every shard's, listed once per path
      (and per archive member for a refusal), first record kept, except that a
      failed-input record the gate counts replaces an accepted one for the same
      path, so an acceptance recorded by one shard cannot hide another shard's
      tool failure.
    * ``dependencies_satisfied``: False if it was False in any shard that ran
      the converter, with the largest candidate count of those shards (missing
      when any of them recorded none) and every distinct reason they recorded
      (``dependency_unavailable_reason``), whole, joined for display. Only a
      count of 0 exempts an unavailable converter, so 0 is kept only when every
      such shard reported 0. A shard that excluded the converter never checked
      its dependencies, so its dependency fields say nothing when another shard
      ran it.
    * ``excluded``: True only if every shard excluded it; a shard that ran it is
      not overridden by one that did not.
    * ``converted_paths``: the union, in order.

    A field no row set is left unset, so a simple dump of agreeing rows is the
    first row's dump. No input is modified; the result is a copy of the first row
    with the merged fields set.
    """
    base = rows[0]
    update: Dict[str, Any] = {}
    fields_set: set = set()
    for row in rows:
        fields_set |= row.model_fields_set

    failures = list(dict.fromkeys(row.failure for row in rows if row.failure))
    if failures:
        update["failure"] = _FAILURE_JOIN.join(failures)

    # The rows that ran the converter decide its dependency fields; an excluded
    # row's say nothing unless every row is excluded.
    ran = [row for row in rows if not row.excluded] or list(rows)
    if not all(row.dependencies_satisfied for row in ran):
        update["dependencies_satisfied"] = False
        unavailable = [row for row in ran if not row.dependencies_satisfied]
        counts = [row.candidate_inputs for row in unavailable]
        if any(count is None for count in counts):
            update["candidate_inputs"] = None
        else:
            update["candidate_inputs"] = max(c for c in counts if c is not None)
        reasons = list(
            dict.fromkeys(
                row.dependency_unavailable_reason
                for row in unavailable
                if row.dependency_unavailable_reason
            )
        )
        # From the rows that ran it alone: with none recorded, the merged row has
        # none, where leaving the field alone kept the first row's, an excluded
        # row's "never checked" text included. A field no row set stays unset,
        # as the docstring promises for every field.
        if reasons:
            update["dependency_unavailable_reason"] = _FAILURE_JOIN.join(reasons)
        elif "dependency_unavailable_reason" in fields_set:
            update["dependency_unavailable_reason"] = None
    elif any(not row.dependencies_satisfied for row in rows):
        # Every row that ran it had its dependencies, and a row that was excluded
        # recorded dependencies_satisfied False: the merged row ran it.
        update["dependencies_satisfied"] = True
        update["dependency_unavailable_reason"] = None
        if "candidate_inputs" in fields_set:
            update["candidate_inputs"] = next(
                row.candidate_inputs for row in ran if row.dependencies_satisfied
            )
    elif "candidate_inputs" in fields_set:
        update["candidate_inputs"] = base.candidate_inputs

    if "excluded" in fields_set:
        update["excluded"] = all(row.excluded for row in rows)

    failed: Dict[str, FailedInputInfo] = {}
    for record in [record for row in rows for record in row.failed_inputs]:
        existing = failed.get(record.path)
        # One record per path, and the one that counts against the completeness
        # gate when the shards disagree: a record one shard's suppression
        # accepted must not hide another shard's tool failure on the same file.
        if existing is None or (waives_gate(existing) and not waives_gate(record)):
            failed[record.path] = record
    if failed:
        update["failed_inputs"] = [r.model_copy() for r in failed.values()]

    refused: Dict[Tuple[str, Optional[str]], RefusedInputInfo] = {}
    for refusal in [refusal for row in rows for refusal in row.refused_inputs]:
        refused.setdefault((refusal.path, refusal.member), refusal)
    if refused:
        update["refused_inputs"] = [r.model_copy() for r in refused.values()]

    if "converted_paths" in fields_set:
        update["converted_paths"] = list(
            dict.fromkeys(path for row in rows for path in row.converted_paths)
        )

    merged = base.model_copy(deep=True)
    for key, value in update.items():
        setattr(merged, key, value)
    return merged


def _union_report_id(
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> str:
    """One ``report_id`` for the merged report, derived from every shard's.

    Each shard is a separate ``ash scan`` and mints its own id. Keeping the base
    shard's would give the merged report the id of a document holding a fraction
    of its findings, so a consumer keyed on the id could not tell the two apart.
    A fresh random id would separate them but make every merge of the same shards
    a different document, which sorting the shards by index exists to avoid.

    So the id is the shard ids' digest, in shard-index order, with the base
    shard's ``generated_at`` as its time: the same shards give the same id in any
    order, other shards give another id, and it has the shape of a scan's id.
    """
    shard_ids = "\n".join(str(shard.metadata.report_id or "") for _, shard, _ in shards)
    digest = hashlib.sha256(shard_ids.encode("utf-8")).hexdigest()[:12]
    try:
        started: Optional[datetime] = datetime.fromisoformat(
            str(shards[0][1].metadata.generated_at)
        )
    except ValueError:
        # Every model sets generated_at when it is built; a results file without a
        # parseable one is not reproducible anyway, so the time is the merge's.
        started = None
    return new_report_id(now=started, token=digest)


#: How much of a text value a WARNING names: a results file can carry any value
#: in metadata, and a 100,000-element list made a 500,151-character log line.
_NAMED_TEXT_LIMIT = 120


def _named_value(value: Any) -> str:
    """*value* as a WARNING names it: text quoted as recorded, cut at 120 characters.

    Not its repr: the warning is shown whole, once, by shown_on_one_line, and a
    repr's escapes were shown again there, so ESC read as the text "\\\\x1b". A
    list or a mapping is no directory, so it is named by its kind and size rather
    than by its items, which are text too; a number, a boolean or None as written.
    """
    if isinstance(value, str):
        if len(value) > _NAMED_TEXT_LIMIT:
            return f"'{value[:_NAMED_TEXT_LIMIT]}...'"
        return f"'{value}'"
    if value is None or isinstance(value, (bool, int, float)):
        return repr(value)
    kind = type(value).__name__
    if isinstance(value, Sized):
        return f"a {kind} of {len(value)} item{'' if len(value) == 1 else 's'}"
    return f"a {kind}"


def _named_values(values: Sequence[Any], limit: int = 5) -> str:
    """The distinct *values*, each shortened, at most *limit* of them."""
    named = sorted({_named_value(value) for value in values})
    shown = ", ".join(named[:limit])
    if len(named) > limit:
        shown += f", and {len(named) - limit} more"
    return shown


def _merge_scan_markers(
    merged: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Make ``scan_source`` and ``changed_files_only`` true of every shard.

    The merged report is a deep copy of the lowest-indexed shard, so without
    this it carried that shard's values whatever the others recorded. The
    aws-security-hub reporter archives a stored finding only under the recorded
    ``scan_source`` and only when ``changed_files_only`` is an explicit False,
    so a shard that scanned another directory, or was filtered to changed files,
    would have the findings it left out read as fixed.

    Shards that disagree on ``scan_source`` (a shard without one, or with a
    value that is not a string, counts as None) leave the merged report with
    none, so nothing is archived, and the values are named in a WARNING.
    ``changed_files_only`` is True when any shard says so, absent when a shard
    does not say, and False only when every shard recorded False.
    """
    recorded = [getattr(shard.metadata, "scan_source", None) for _, shard, _ in shards]
    # metadata keeps unknown keys as given, so a results file can carry a list or
    # a mapping here, which is no directory and cannot go in a set.
    sources = [source if isinstance(source, str) else None for source in recorded]
    if len(set(sources)) > 1:
        reason = "The shards record different scanned directories"
    elif any(
        source is None and value is not None for source, value in zip(sources, recorded)
    ):
        reason = "The shards record no scanned directory that is a string"
    else:
        reason = None
    if reason is not None:
        ASH_LOGGER.warning(
            shown_on_one_line(
                f"{reason} (scan_source {_named_values(recorded)}), so the merged "
                "results record none and aws-security-hub archives nothing from "
                "them."
            ),
            extra=NO_MARKUP,
        )
        setattr(merged.metadata, "scan_source", None)

    markers = [
        getattr(shard.metadata, "changed_files_only", None) for _, shard, _ in shards
    ]
    if any(marker is True for marker in markers):
        setattr(merged.metadata, "changed_files_only", True)
    elif any(marker is not False for marker in markers):
        setattr(merged.metadata, "changed_files_only", None)


def _adopt_owning_shard_results(
    merged: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
    owner_by_scanner: Dict[str, int],
) -> None:
    """Keep only the owning shard's status for each scanner.

    This is the step that decides whether the merged report is usable at all.
    Every shard records the scanners it did *not* own as excluded -- status
    SKIPPED in ``scanner_results``, and a skip marker under
    ``additional_reports[name]["None"]``. A shard's own scanners get real entries
    under ``additional_reports[name]["source"]``.

    Both matter, and ``additional_reports`` matters more.
    ``ScannerStatisticsCalculator.get_scanner_status_info`` consults
    ``additional_reports[name]["None"]`` *before* ``scanner_results``, so a merged
    report that kept both a skip marker and a real entry for one scanner would
    read ``excluded=True`` from the marker. ``get_unified_scanner_metrics`` maps
    excluded to SKIPPED regardless of the finding count, so every sharded scanner
    would report SKIPPED with its findings present but attributed to a scanner
    the report claims never ran -- and ``summary_stats.skipped`` would count the
    whole scanner set. Unioning these two dictionaries is the single mistake that
    turns a working merge into a report that says nothing ran.

    Ownership comes from ``assigned_scanners`` rather than from sniffing statuses,
    because that field *is* the record of who was asked to run what.
    ``ShardAssignment`` documents that it holds the assignment and not the
    outcome, which is exactly the property needed here: a scanner that the
    operator excluded globally, or whose dependencies were missing, still has a
    single owning shard, and that shard's SKIPPED or MISSING entry is the true
    one. Inferring ownership from "whichever entry is not SKIPPED" would find no
    owner for those scanners and fall back to an arbitrary shard's marker.
    """
    scanner_results: Dict[str, Any] = {}
    additional_reports: Dict[str, Any] = {}

    # Copies of the owning shard's entries, not the entries: the merged set is
    # masked in place afterwards, and merge_shard_results promises its inputs
    # stay as they were loaded.
    for position, (_, shard, _) in enumerate(shards):
        for name, entry in shard.scanner_results.items():
            if owner_by_scanner.get(_normalized(name)) == position:
                scanner_results[name] = _copied(entry)
        for name, report in shard.additional_reports.items():
            if owner_by_scanner.get(_normalized(name)) == position:
                additional_reports[name] = _copied(report)

    # Entries whose key names no known scanner are carried through untouched, the
    # first shard's record kept. additional_reports is a free-form dictionary and
    # a plugin may write to it under a key that is not a scanner name; dropping
    # those would lose data that has nothing to do with sharding. The same holds
    # for a scanner_results row that no shard owns: the ERROR or MISSING row of a
    # scanner that failed to construct, or of a plugin module that failed to
    # import, which _verify_scanner_union exempts from its refusal so that the
    # merged report still names it. Dropping it here would undo that exemption.
    for _, shard, _ in shards:
        for name, entry in shard.scanner_results.items():
            if _normalized(name) not in owner_by_scanner:
                scanner_results.setdefault(name, _copied(entry))
        for name, report in shard.additional_reports.items():
            if _normalized(name) not in owner_by_scanner:
                additional_reports.setdefault(name, _copied(report))
    merged.scanner_results = scanner_results
    merged.additional_reports = additional_reports


def _record_merge_provenance(
    merged: AshAggregatedResults,
    shards: Sequence[Tuple[Path, AshAggregatedResults, ShardAssignment]],
) -> None:
    """Replace the base shard's provenance with the merge's own.

    The ``shard`` value is cleared rather than updated. Leaving it would describe
    the merged report as one shard of n, so re-merging an output directory would
    be accepted and would report a whole scan as a fraction of itself.

    Cleared to None rather than deleted, which was tried and rejected.
    ``ReportMetadata`` declares ``shard`` as a real field, and pydantic does allow
    ``delattr`` on a declared field -- but afterwards a plain
    ``results.metadata.shard`` raises AttributeError instead of returning the
    field's default, and the field vanishes from ``model_dump_json`` entirely.
    That leaves a booby-trapped model for every consumer that reads the attribute
    without a default: reporters, the committed JSON schema, and any later caller.
    None is the field's own default, serializes as ``"shard": null``, and
    :func:`read_shard_assignment` treats it as absent, so clearing achieves
    everything deleting did without the landmine.
    """
    for carrier in (merged, merged.metadata):
        if getattr(carrier, SHARD_PROVENANCE_KEY, None) is not None:
            setattr(carrier, SHARD_PROVENANCE_KEY, None)

    setattr(merged.metadata, MERGED_SHARD_COUNT_KEY, shards[0][2].shard_count)
    setattr(
        merged.metadata,
        MERGED_SHARD_INDICES_KEY,
        [assignment.shard_index for _, _, assignment in shards],
    )


def _converter_acceptance_ids(merged: AshAggregatedResults, config: Any) -> Set[str]:
    """The suppression ids the shards' convert phases registered as used.

    The convert phase puts two kinds of id in ``used_suppressions``: the
    ``accepted_by`` a converter wrote on a failed-input record when a suppression
    accepted it, and, for an accepted record carrying no id (a write that failed,
    a third-party converter's record, a results file written before the field
    existed), the written id of the entry its path matches now. Both are read
    back here the way the phase derived them, from the merged converter rows,
    so the ``--ignore-suppressions`` clear keeps exactly what the phase recorded.
    A record whose path matches no entry any more names nothing, as it would
    there.
    """
    from automated_security_helper.utils.suppression_matcher import (
        accepting_unconverted_input,
        recorded_suppressions,
        written_suppression_id,
    )

    ids: Set[str] = set()
    uncovered: List[FailedInputInfo] = []
    for row in merged.converter_results.values():
        for record in getattr(row, "failed_inputs", None) or []:
            if not getattr(record, "accepted", False):
                continue
            if getattr(record, "kind", None) != "input":
                continue
            carried = getattr(record, "accepted_by", None)
            if isinstance(carried, str) and carried:
                ids.add(carried)
            else:
                uncovered.append(record)
    if not uncovered:
        return ids
    settings = getattr(config, "global_settings", None)
    suppressions = getattr(settings, "suppressions", None)
    recorded = recorded_suppressions(config)
    for record in uncovered:
        accepting = accepting_unconverted_input(
            str(getattr(record, "path", "")), suppressions
        )
        if accepting is not None:
            ids.add(written_suppression_id(accepting, recorded))
    return ids


def apply_aggregated_suppressions(
    merged: AshAggregatedResults, plugin_context: PluginContext
) -> AshAggregatedResults:
    """Run the aggregated suppression pass ``ash scan`` runs, over the merged SARIF.

    Why this has to exist here
    --------------------------
    ``AshExecutionEngine`` applies ``apply_suppressions_to_sarif`` to the
    *aggregated* SARIF immediately before the report phase, and then re-runs
    ``populate_metrics_from_unified_source`` so the exit code reflects the
    post-suppression state. Its stated reason is that the per-scanner passes miss
    findings whose paths only become matchable after merge and normalization.

    ``ash merge`` folded n shard SARIFs and went straight to metrics and reports,
    so nothing ever applied suppressions to the cross-shard product. A suppression
    that only matches post-merge therefore applied in an unsharded scan and not in
    a sharded one: ``ash merge`` exited 2 where ``ash scan`` exited 0 on identical
    inputs. That is precisely the divergence ``_merged_exit_code``'s own docstring
    argues must not exist, and it is worse than an ordinary bug because the two
    commands are supposed to be interchangeable -- CI gates on the sharded one.

    Why the ignore_suppressions guard is duplicated from the engine
    --------------------------------------------------------------
    ``apply_suppressions_to_sarif`` also checks ``ignore_suppressions`` itself, so
    the guard here looks redundant, and on the configuration the tests cover it
    provably is: calling the function with ``ignore_suppressions=True`` was
    measured to produce byte-identical SARIF to not calling it at all, and
    deleting this condition kills no test.

    It is kept for two reasons that the measurement does not cover. The engine
    carries the identical guard, and the property being fixed is that the two
    paths agree -- a merge path relying on the callee's check while the scan path
    relies on the caller's would drift apart the moment either changed. And the
    equivalence was only measured for a config with no ``ignore_paths``: inside
    the function, the ignore-path branch is gated on ``not ignore_suppressions``
    combined with a path match, so a config that sets ``ignore_paths`` could
    behave differently between "skipped" and "called with the flag set". Skipping
    the call is what ``ash scan`` does, so skipping it is what keeps the verdicts
    equal in the configurations no fixture here exercises.

    Under the flag ``apply_suppressions_to_sarif`` is skipped, and the
    suppressions ASH applied on the shards are lifted
    (:func:`lift_ash_suppressions`). The shards ran without the flag, so their
    results arrive carrying the config and inline suppressions each shard's own
    pass attached, and the metrics count a result with any suppression as
    suppressed. Left in place, the flag changed nothing on a sharded scan while
    its help text promised every finding regardless of suppression status; a
    scan run with the flag attaches none of them, so lifting them is what makes
    the two commands answer alike on the suppressions. Not on the ignore paths: a
    shard's ignore path dropped the result from the shard's SARIF rather than
    attaching a suppression, so the merge has nothing to lift there, and a scan
    run with the flag keeps results the sharded run under the flag cannot bring
    back. ``verify_verdict_settings_agree`` therefore still refuses shards that
    disagree on their ignore paths under the flag. The output-directory exclusion is not applied here in
    either case -- each shard already dropped its own output-directory results,
    as the comment at the call site says.

    Args:
        merged: The merged results, with metrics already populated from the union.
        plugin_context: Carries the scan's own config and ``ignore_suppressions``.

    Returns:
        *merged*, with suppressions applied and metrics recomputed. Returned
        rather than mutated in place only because
        ``populate_metrics_from_unified_source`` returns the model.
    """
    if merged is not None and merged.sarif is not None:
        # Imported here, matching the engine, which imports it inside the report
        # branch. sarif_utils pulls in the SARIF model and the config tree, and
        # ``ash merge`` reaches this point only after a successful merge.
        from automated_security_helper.utils.sarif_utils import (
            apply_suppressions_to_sarif,
        )

        # The output-directory exclusion is not applied again. Each shard already
        # dropped the results in its own output directories that are not files
        # the repository committed, with its own git answer and run ID. The merge
        # has no run ID and may run outside git, where git's answer is that
        # nothing is committed, so deciding again dropped a committed file every
        # shard kept. The merge keeps what the shards kept.
        # The source directory's basename is not stripped off the URIs either.
        # The pass strips it for offline opengrep, which writes URIs prefixed with
        # the scanned directory's name; the merged URIs are already relative to
        # each shard's scanned tree, and the merge's source directory is the
        # collector's working directory, so the strip read ``src/a.py`` as
        # ``a.py`` whenever the collector ran from a directory named ``src``, and
        # every suppression, ignore path and finding id keyed on the path moved
        # with it.
        if not plugin_context.ignore_suppressions:
            merged.sarif = apply_suppressions_to_sarif(
                sarif_report=merged.sarif,
                plugin_context=plugin_context,
                used_suppressions=getattr(merged, "used_suppressions", None),
                exclude_output_dir=False,
                strip_source_dir_basename=False,
            )
        else:
            lift_ash_suppressions(merged.sarif)
            # The record goes with the suppressions. ``used_suppressions`` is the
            # union of what the shards' passes matched; a scan run with the flag
            # never calls apply_suppressions_to_sarif, which is what fills it, so
            # its results record none, and a merged results file whose SARIF now
            # carries none of the shards' suppressions must not say they matched.
            # The convert phase registers another kind of use in the same set:
            # the id of the ``ash-unconverted-input`` suppression that accepted
            # a failed input on a shard. The lift undoes nothing of that (the
            # input was never converted, flag or no flag), so those ids stay.
            merged.used_suppressions.intersection_update(
                _converter_acceptance_ids(merged, plugin_context.config)
            )
            # Written into the results for a later ``ash report`` over the file,
            # whose context carries no flag: the unused-suppressions reporter
            # reads this field and says the suppressions were not evaluated,
            # instead of subtracting the emptied record from the configured list
            # and offering every entry as unused. ReportMetadata admits the
            # field (extra="allow") ahead of its declaration.
            merged.metadata.suppressions_ignored = True
            _warn_ignore_paths_the_flag_cannot_lift(plugin_context.config)

    # Recomputed unconditionally, not only when suppressions ran. Under
    # ``--ignore-suppressions`` the counts change when a suppression the shards
    # applied was lifted; making this conditional would put the "did the counts
    # get refreshed" question on the same branch as "did suppressions run", and the
    # exit code depends on the first.
    return populate_metrics_from_unified_source(aggregated_results=merged)


def _warn_ignore_paths_the_flag_cannot_lift(config: Any) -> None:
    """Name the ignore paths the shards scanned under, which the flag leaves in force.

    ``--ignore-suppressions`` promises every finding regardless of suppression
    status, as ``ash scan --ignore-suppressions`` gives it. An ignore path is not
    a suppression the merge can lift: each shard dropped the results under it from
    its own SARIF before the merge (``apply_suppressions_to_sarif``), and a dropped
    result is not in the merge to bring back, so a sharded run under the flag
    reports fewer findings than the scan would. Said at WARNING, with the paths,
    so the difference is not read as the flag having no effect. Silent when the
    merged config names none.
    """
    settings = getattr(config, "global_settings", None)
    ignored = [
        str(getattr(entry, "path", entry))
        for entry in getattr(settings, "ignore_paths", None) or []
    ]
    if not ignored:
        return
    ASH_LOGGER.warning(
        shown_on_one_line(
            f"--ignore-suppressions lifts the suppressions the shards attached, "
            f"not the {len(ignored)} ignore path(s) they scanned under "
            f"({', '.join(ignored)}): each shard dropped the results under them "
            f"from its own results before the merge, and a dropped result cannot "
            f"be brought back here, where ash scan --ignore-suppressions keeps "
            f"them. For every finding, scan without the ignore paths or merge "
            f"shards that recorded none."
        ),
        extra=NO_MARKUP,
    )


def _is_ash_applied_suppression(suppression: Any) -> bool:
    """Whether ``apply_suppressions_to_sarif`` attached *suppression*.

    Read from the structured mark first: every suppression that function attaches
    carries ``properties.ashApplied`` (``sarif_utils.ash_applied_properties``),
    and a client-supplied one ``clientSupplied`` as well, which counts too: it is
    ASH's, attached by the same function and by nothing else, so a scan run with
    ``--ignore-suppressions``, which never calls that function
    (``ScanResultProcessor``), never carries it. A shard written before the mark
    existed is read by the justification prefixes that module writes
    (``ASH_SUPPRESSION_JUSTIFICATION_PREFIXES``); a scanner's own suppression
    carries neither mark nor prefix.
    """
    from automated_security_helper.utils.sarif_utils import (
        ASH_SUPPRESSION_JUSTIFICATION_PREFIXES,
    )

    properties = getattr(suppression, "properties", None)
    if getattr(properties, "ashApplied", None) is True:
        return True
    if getattr(properties, "clientSupplied", None) is True:
        return True
    justification = getattr(suppression, "justification", None) or ""
    return justification.startswith(ASH_SUPPRESSION_JUSTIFICATION_PREFIXES)


def lift_ash_suppressions(sarif_report: Any) -> int:
    """Remove the suppressions ASH applied from every result of *sarif_report*.

    What ``--ignore-suppressions`` means on a merge. ``ash scan`` run with the
    flag never calls ``apply_suppressions_to_sarif`` (``ScanResultProcessor``
    skips it and runs the output-directory exclusion alone), so no config, inline
    or client-supplied suppression reaches its results and every such finding
    counts as actionable; the shards of a sharded scan ran without the flag and
    attached theirs, so the merge removes them again to answer the same question.
    Only what that function attaches is removed: a suppression a scanner wrote
    into its own SARIF stays, as it stays on a scan run with the flag. A result
    left with no suppression carries ``None``, the shape of a result never
    suppressed.

    Returns the number of suppressions removed.
    """
    removed = 0
    for run in getattr(sarif_report, "runs", None) or []:
        for result in getattr(run, "results", None) or []:
            if not result.suppressions:
                continue
            kept = [
                s for s in result.suppressions if not _is_ash_applied_suppression(s)
            ]
            removed += len(result.suppressions) - len(kept)
            result.suppressions = kept or None
    return removed


# ---------------------------------------------------------------------------
# The recorded configuration
# ---------------------------------------------------------------------------


def resolve_operator_config(config_path: Optional[str]) -> AshConfig:
    """The operator's trusted base: the defaults, or ``--config`` (or ``ASH_CONFIG``).

    Resolved the way ``ash report`` resolves its config, except that a
    ``--config`` naming nothing readable is refused rather than replaced by the
    defaults: a merge whose operator values silently became the defaults would
    send its reports somewhere other than the operator chose. The file is read
    once, here; the rest of the merge uses what this returns. A refusal quotes the
    path with its control characters escaped (``describe_config_path``).

    Raises:
        ASHConfigSourceError: When the path is not a file, or the file cannot be
            read or parsed.
        ASHConfigValidationError: When the file does not validate.
    """
    if config_path is None:
        return resolve_config(config_path=None)
    path = Path(config_path)
    try:
        is_file = path.is_file()
    except OSError as exc:
        # Before Python 3.14, Path.is_file answers False for ENOENT, ENOTDIR,
        # EBADF and ELOOP and re-raises every other stat error: a parent this
        # user cannot search (EACCES), a name over the limit (ENAMETOOLONG).
        # Such a file cannot be used, so it is refused with exit 3 in the read
        # arm's words below, never a traceback. From 3.14 it answers False for
        # every OSError, so those two reach the "does not exist or is not a
        # file" refusal after this handler instead: still exit 3, other words.
        # (check_config_path asks os.stat, which reads all of them as one.)
        raise ASHConfigSourceError(
            f"--config {describe_config_path(path)} could not be read: "
            f"{escape_controls_in(exc, path_spellings(path))}"
        ) from exc
    if not is_file:
        raise ASHConfigSourceError(
            f"--config {describe_config_path(path)} does not exist or is not a file."
        )
    try:
        config = resolve_config(config_path=path, fallback_to_default=False)
    except ASHConfigValidationError:
        raise
    except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
        # json.JSONDecodeError is a ValueError.
        raise ASHConfigSourceError(
            f"--config {describe_config_path(path)} could not be read: "
            f"{escape_controls_in(exc, path_spellings(path))}"
        ) from exc
    if config is None:
        raise ASHConfigSourceError(
            f"--config {describe_config_path(path)} could not be read."
        )
    return config


def apply_operator_overrides(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
    config_overrides: Sequence[str],
) -> None:
    """Apply ``--config-overrides`` to each shard's recorded config, in place.

    Called before anything reads those configs, so the completion gate, the
    verdict and the reporters all see the operator's values. A shard that
    recorded no config is left without one, so
    :func:`_resolve_require_scanner_completion` still passes over it.

    Raises:
        ASHConfigValidationError: If an override cannot be applied.
    """
    if not config_overrides:
        return
    for _, results in loaded:
        if results.ash_config is not None:
            results.ash_config = apply_config_overrides(
                results.ash_config, list(config_overrides)
            )


def supply_unread_recorded_fields(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
    trusted_config: AshConfig,
    config_overrides: Sequence[str],
    cli_values: Optional[Dict[str, Any]] = None,
) -> None:
    """Supply, from the operator, each recorded field a shard's results could not
    read, in place.

    A shard records a value its scan read from the environment as the reference
    its config file wrote. A fixed-choice field such as ``severity_threshold``
    cannot hold one, so the shard's record reads it as the field's default and
    lists it (``AshAggregatedResults.validate_ash_config``,
    ``config/recorded_config.py``). The merge computes its reports and its
    verdict from these fields, so each one comes from ``--config-overrides`` or
    the file ``--config`` (or ``ASH_CONFIG``) names, or the merge is refused: the
    default in place of the scan's severity threshold could drop findings from the
    merged report.

    The overrides are already on each shard's record
    (:func:`apply_operator_overrides`) and not on ``trusted_config``, so the
    operator's configuration is read with them applied to a copy: a field an
    override names counts as supplied and takes the value the override gave it,
    and one the file writes takes the file's.

    ``cli_values`` maps a field to the value the command line gave it
    (``--output-formats`` for ``output_formats``), in the shape of
    :func:`verify_verdict_settings_agree`'s: ``None`` or an empty value is a flag
    that was not given and supplies nothing. A given value supplies its field as
    ``--config-overrides '<field>=<value>'`` does and is applied after the
    overrides, so it replaces what they gave the field, as the flag replaces the
    formats the merge reports with.

    Every shard is checked before any is changed, and the refusal is one for all
    of them: it names each field with its reference once, and under it every
    shard and results file that recorded that reference, as
    :func:`verify_verdict_settings_agree` does for a setting the shards disagree
    on, so the operator supplies every field in one run.

    Raises:
        ASHConfigValidationError: A field neither supplies, named with the
            reference, never a value.
    """
    if not any(unreadable_references(results.ash_config) for _, results in loaded):
        return
    given_on_command_line = [
        f"{field}={json.dumps(value)}"
        for field, value in (cli_values or {}).items()
        if value
    ]
    operator_overrides = [*config_overrides, *given_on_command_line]
    operator = (
        apply_config_overrides(trusted_config, operator_overrides)
        if operator_overrides
        else trusted_config
    )
    missing = [
        (path, results, field, reference)
        for path, results in _in_index_order(loaded)
        for field, reference in unsupplied_references(results.ash_config, operator)
    ]
    if missing:
        raise unsupplied_refusal(
            _named_with_shards(missing),
            [(field, reference) for _, _, field, reference in missing],
            HOW_TO_SUPPLY,
        )
    for _, results in loaded:
        take_own_values(
            results.ash_config, operator, refuse_unless_supplied=HOW_TO_SUPPLY
        )


def confine_recorded_config(
    config: AshConfig,
    trusted_config: AshConfig,
    config_overrides: Sequence[str],
    results_file: Path,
) -> None:
    """Hold a shard's recorded config to the rules for a config file in the scanned tree.

    Runs ``confine_to_trusted_base``, the steps ``resolve_config`` runs for such a
    file, with ``SHARD_RECORDED`` as the source: the warnings name
    ``results_file`` and give ``ash merge``'s options as the fix, and an
    ``ash_plugin_modules`` entry the operator's configuration does not name is
    dropped. ``confine_reporter_destinations`` also records the trusted base on
    ``config`` for ``confine_declared_reporter_destinations``, which the caller
    runs with the same source once the plugin modules are loaded.

    Args:
        config: The merged report's config, changed in place.
        trusted_config: The operator's config, without ``config_overrides``.
        config_overrides: ``--config-overrides``, replayed onto ``trusted_config``.
        results_file: The results file ``config`` was recorded in.
    """
    confine_to_trusted_base(
        config,
        trusted_config,
        list(config_overrides),
        Path.cwd(),
        [results_file],
        source=SHARD_RECORDED,
    )


def _in_index_order(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
) -> List[Tuple[Path, AshAggregatedResults]]:
    """``loaded`` by shard index, with any file that carries no provenance last.

    The order :func:`merge_shard_results` takes the merged report's identity in,
    for the readers of the recorded config that run before it.
    """

    def position(entry: Tuple[Path, AshAggregatedResults]) -> Tuple[bool, int]:
        assignment = read_shard_assignment(entry[1])
        return (assignment is None, assignment.shard_index if assignment else 0)

    return sorted(loaded, key=position)


def _shard_label(results: AshAggregatedResults) -> str:
    """How a refusal names the shard that recorded something."""
    assignment = read_shard_assignment(results)
    if assignment is None:
        return "a shard without provenance"
    return f"shard {assignment.shard_index}"


def _listed(items: Sequence[str]) -> str:
    """``items`` as a phrase: one alone, two joined by "and", more as a comma list
    with "and" before the last."""
    if len(items) <= 2:
        return " and ".join(items)
    return f"{', '.join(items[:-1])}, and {items[-1]}"


def _named_with_shards(
    missing: Sequence[Tuple[Path, AshAggregatedResults, str, str]],
) -> str:
    """Each ``(field, reference)`` of ``missing`` once, with every shard and results
    file that recorded it. ``missing`` comes in shard-index order, with a shard
    whose results carry no shard assignment last (:func:`_in_index_order`), which
    is not the order the shards were given on the command line.

    The common pipeline records one reference in every shard, so the entry is
    per reference and not per shard; the same field recorded as another
    reference by another shard is another entry.
    """
    recorded_in: Dict[Tuple[str, str], List[str]] = {}
    for path, results, field, reference in missing:
        recorded_in.setdefault((field, reference), []).append(
            f"{_shard_label(results)} ({path.as_posix()})"
        )
    return "; ".join(
        f"{field} is recorded as {reference} in {_listed(places)}"
        for (field, reference), places in recorded_in.items()
    )


def _base_results_file(loaded: Sequence[Tuple[Path, AshAggregatedResults]]) -> Path:
    """The results file of the lowest-indexed shard, which supplies the merged config."""
    return _in_index_order(loaded)[0][0]


def _as_written(value: Any) -> Any:
    """``value`` with each list entry reduced to what a config file writes.

    A suppression or ignore path dumps every field, ``None`` for the ones left
    out, and ASH's own ``client_supplied`` mark. Neither is part of what was
    written, so a file that omits them compares equal to a full dump, and an
    override suggested from them repeats only what the operator wrote.
    """
    if not isinstance(value, list):
        return value
    return [
        {
            key: item_value
            for key, item_value in item.items()
            if key != "client_supplied" and item_value is not None
        }
        if isinstance(item, dict)
        else item
        for item in value
    ]


def _verdict_settings(dumped: Dict[str, Any]) -> Dict[str, Any]:
    """The settings of a dumped config that decide the merged verdict, by override key.

    ``dumped`` is ``AshConfig.model_dump(mode="json", by_alias=True)``, with
    ``exclude_unset`` for the settings a file sets. The keys are the
    ``--config-overrides`` spelling of each setting, and list values are reduced
    to what a file writes (``_as_written``).
    """
    settings: Dict[str, Any] = {}
    for name, value in dumped.items():
        if name in ("fail_on_findings", "fail_on_incomplete_scanners") or (
            name.startswith("content_db_staleness")
        ):
            settings[name] = _as_written(value)
    global_settings = dumped.get("global_settings") or {}
    for name in ("severity_threshold", "suppressions", "ignore_paths"):
        if name in global_settings:
            settings[f"global_settings.{name}"] = _as_written(global_settings[name])
    for scanner, section in (dumped.get("scanners") or {}).items():
        options = section.get("options") if isinstance(section, dict) else None
        if isinstance(options, dict) and "severity_threshold" in options:
            key = f"scanners.{scanner}.options.severity_threshold"
            settings[key] = options["severity_threshold"]
    return settings


def _recorded_verdict_settings(results: AshAggregatedResults) -> Dict[str, Any]:
    config = results.ash_config
    if config is None:
        return {}
    return _verdict_settings(config.model_dump(mode="json", by_alias=True))


def _shown_setting(value: Any) -> str:
    text = json.dumps(value, sort_keys=True)
    return text if len(text) <= 60 else text[:57] + "..."


#: The verdict settings ``ash merge`` has a flag for, with the flag's spelling for
#: true and for false. A flag that is given decides the setting for the merge.
VERDICT_FLAGS: Dict[str, Tuple[str, str]] = {
    "fail_on_findings": ("--fail-on-findings", "--no-fail-on-findings"),
    "fail_on_incomplete_scanners": (
        "--fail-on-incomplete-scanners",
        "--no-fail-on-incomplete-scanners",
    ),
}


def _decided_by_flags(cli_values: Optional[Dict[str, Optional[bool]]]) -> set[str]:
    """The verdict settings a flag given on the command line decides."""
    return {key for key, value in (cli_values or {}).items() if value is not None}


class ShardSettingsDisagreeError(ASHConfigValidationError):
    """The shards' recorded configurations disagree on a setting the verdict reads.

    The one configuration refusal of ``ash merge`` that is written on several
    lines on purpose (a header, one line per setting, the advice), and printed on
    them (``_invalid_config_lines``). Every other ``ASHConfigValidationError`` the
    merge prints can quote a value the operator typed, a ``--config-overrides``
    entry among them, so it is printed on one line (``_invalid_config_text``).
    """


#: The settings read for the exit code that decide nothing under
#: ``--ignore-suppressions``: the suppression pass that reads them is skipped and
#: the shards' own suppressions are lifted, so two shards that disagree on them
#: still get one exit code. ``global_settings.ignore_paths`` is not among them:
#: a shard's ignore path does not attach a suppression, it drops the result from
#: the shard's SARIF (``apply_suppressions_to_sarif``), and a dropped result is
#: not in the merge to lift. Two shards that disagree on their ignore paths hand
#: the merge two different sets of findings, so they are refused under the flag
#: as without it.
_SUPPRESSION_SETTINGS = frozenset({"global_settings.suppressions"})


def verify_verdict_settings_agree(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
    cli_values: Optional[Dict[str, Optional[bool]]] = None,
    ignore_suppressions: bool = False,
) -> None:
    """Refuse shards whose recorded configs disagree on a setting the verdict reads.

    One verdict covers the merged scan, and it is computed from one config. Taking
    the lowest-indexed shard's value for every shard would let one shard's
    ``fail_on_findings: false`` or suppressions decide for findings another shard
    produced under different settings. Compared after ``--config-overrides`` are
    applied, so an override that sets the value for every shard settles it, and a
    setting the command line's flag decides (``cli_values``, keyed as
    ``VERDICT_FLAGS``) is not compared at all. Under ``--ignore-suppressions``
    the suppression setting is not compared either: that flag skips the pass
    that reads it and lifts the suppressions the shards attached, so it cannot
    move the merged exit code, and refusing on it would deny the operator the
    one flag that exists to take the suppressions out of it. The ignore-path
    setting IS still compared under the flag: a shard's ignore path dropped
    results from the shard's SARIF, nothing lifts a dropped result, so shards
    that disagree on it produced different findings. A shard that recorded no configuration
    at all is left out: it has no value to disagree with, and
    ``merge_shard_results`` refuses it, naming it as one with no scan configuration.

    Raises:
        ShardSettingsDisagreeError: Naming each setting that differs and every
            shard's value for it. An ``ASHConfigValidationError``.
    """
    decided = _decided_by_flags(cli_values)
    if ignore_suppressions:
        decided = decided | _SUPPRESSION_SETTINGS
    shards = []
    for path, results in _in_index_order(loaded):
        if results.ash_config is None:
            continue
        shards.append(
            (_shard_label(results), path, _recorded_verdict_settings(results))
        )
    keys = sorted(
        {key for _, _, settings in shards for key in settings if key not in decided}
    )
    differing = [
        key
        for key in keys
        if len(
            {json.dumps(settings.get(key), sort_keys=True) for *_, settings in shards}
        )
        > 1
    ]
    if not differing:
        return
    lines = [
        f"{key}: "
        + "; ".join(
            f"{label} ({path.as_posix()}) {_shown_setting(settings.get(key))}"
            for label, path, settings in shards
        )
        for key in differing
    ]
    flags = [
        f"{VERDICT_FLAGS[key][0]} or {VERDICT_FLAGS[key][1]} for {key}"
        for key in differing
        if key in VERDICT_FLAGS
    ]
    raise ShardSettingsDisagreeError(
        "the shards' recorded configurations disagree on settings that decide the "
        "merged verdict:\n  " + "\n  ".join(lines) + "\nOne verdict covers the "
        "merged scan, so ash merge does not take one shard's value for the others. "
        "Run every shard with the same configuration, or set the value for all of "
        "them with --config-overrides"
        + (f", or with {', '.join(flags)}" if flags else "")
        + "."
    )


def _override_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return json.dumps(value)


#: Follows a suggested override that had to be quoted. The quoting is a POSIX
#: shell's, which PowerShell and cmd.exe do not read the same way.
POSIX_QUOTING_NOTE = (
    "(quoted for a POSIX shell; in PowerShell or cmd.exe, quote it for that shell)"
)


def _override_suggestion(key: str, value: Any) -> str:
    """``--config-overrides`` setting ``key`` to ``value``, as one argument for a shell.

    A list or mapping holds spaces and double quotes, and a string can hold
    anything, so the argument is quoted the way a POSIX shell reads it back, and
    a quoted one is followed by ``POSIX_QUOTING_NOTE``. ``key`` ends with ``+``
    for an appending override.
    """
    text = f"{key}={_override_value(value)}"
    argument = shlex.quote(text)
    if argument == text:
        return f"--config-overrides {argument}"
    return f"--config-overrides {argument} {POSIX_QUOTING_NOTE}"


def warn_on_ignored_operator_verdict_settings(
    trusted_config: AshConfig,
    recorded: AshConfig,
    cli_values: Optional[Dict[str, Optional[bool]]] = None,
) -> None:
    """Name each verdict setting ``--config`` sets that the recorded config decides.

    The verdict follows the scan's own configuration, so a setting the operator's
    file sets for it does not apply at merge time. The exception is a field a
    shard recorded as a reference its field cannot hold, which takes the
    operator's value (:func:`supply_unread_recorded_fields`) before this runs:
    the value ``--config-overrides`` gives it when it names the field, else the
    file's. A field that took the file's value matches it and is not named here.
    Only the settings the file writes are compared, so a file that sets only
    reporters warns about nothing, and a setting a flag given on the command line
    decides (``cli_values``) is not reported, since the flag applies.
    """
    decided = _decided_by_flags(cli_values)
    operator = _verdict_settings(
        trusted_config.model_dump(mode="json", by_alias=True, exclude_unset=True)
    )
    if not operator:
        return
    shards = _verdict_settings(recorded.model_dump(mode="json", by_alias=True))
    for key, value in operator.items():
        if key in decided or json.dumps(value, sort_keys=True) == json.dumps(
            shards.get(key), sort_keys=True
        ):
            continue
        flag = ""
        if key in VERDICT_FLAGS and isinstance(value, bool):
            flag = f" or {VERDICT_FLAGS[key][0 if value else 1]}"
        # Redacted with what the operator's config read from the environment:
        # the line quotes the setting's value, which can hold one (an ignore
        # path's reason read with !ENV, say).
        message = (
            f"ash merge's --config sets {key} to {_shown_setting(value)}, and the "
            f"shards recorded {_shown_setting(shards.get(key))}. The verdict "
            "follows the shards' own configuration, so their value applies. To "
            "apply yours, pass "
            f"{_override_suggestion(key, value)}{flag}."
        )
        ASH_LOGGER.warning(
            text_without_values(message, config_environment_values(trusted_config))
        )


def _section_dict(section: Any) -> Dict[str, Any]:
    if isinstance(section, dict):
        return section
    if hasattr(section, "model_dump"):
        return section.model_dump(by_alias=True)
    return {}


def _apply_hint(key: str, value: Any) -> str:
    """The ``--config-overrides`` that sets ``key`` to ``value``, shortened when long."""
    if len(_override_value(value)) > 60:
        return f"pass its value with --config-overrides {key}=VALUE"
    return f"pass {_override_suggestion(key, value)}"


def warn_on_unapplied_operator_settings(
    trusted_config: AshConfig,
    effective: AshConfig,
    reporter_classes: Sequence[type],
) -> None:
    """Name each reporter setting ``--config`` sets that does not apply.

    ``--config`` supplies the operator's values for the reporter sections the
    shards' recorded config names, and adds no section: a reporter's ``enabled``
    or destination option for a section the shards did not record is not used.
    Each such entry is named with the ``--config-overrides`` that would add it.
    Compared after every confinement step and the plugin load, so only what
    really did not apply is named. The plugin modules ``--config`` names always
    apply: they are the ones the merge loads (``confine_recorded_config``).
    """
    destinations: Dict[str, Tuple[str, ...]] = dict(REPORTER_DESTINATION_OPTIONS)
    destinations.update(declared_destination_options(reporter_classes))
    defaults: Dict[str, bool] = dict(REPORTER_ENABLED_DEFAULTS)
    defaults.update(declared_enabled_defaults(reporter_classes))
    written = trusted_config.model_dump(mode="json", by_alias=True, exclude_unset=True)
    for section_key, section in (written.get("reporters") or {}).items():
        if not isinstance(section, dict):
            continue
        plugin = next(
            (
                known
                for known in destinations
                if reduced_plugin_name(known) == reduced_plugin_name(section_key)
            ),
            None,
        )
        if plugin is None:
            continue
        current = _section_dict(effective.get_plugin_config("reporter", plugin))
        unapplied: List[Tuple[str, Any]] = []
        if "enabled" in section and bool(
            current.get("enabled", defaults.get(plugin, True))
        ) != bool(section["enabled"]):
            unapplied.append((f"reporters.{section_key}.enabled", section["enabled"]))
        options = section.get("options") or {}
        current_options = current.get("options") or {}
        for option in destinations[plugin]:
            if option in options and current_options.get(option) != options[option]:
                unapplied.append(
                    (f"reporters.{section_key}.options.{option}", options[option])
                )
        for key, value in unapplied:
            # Redacted as the settings line above is: the hint quotes the
            # option's value, which the operator's config can have read from
            # the environment.
            message = (
                f"ash merge's --config sets {key}, which does not apply: the shards "
                f"recorded no {section_key} section to take it, and --config supplies "
                "values for what the shards recorded without adding to it. To apply "
                f"it, {_apply_hint(key, value)}."
            )
            ASH_LOGGER.warning(
                text_without_values(message, config_environment_values(trusted_config))
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_output_formats(raw: Optional[List[str]]) -> List[str]:
    """Split and validate comma-separated ``--output-formats`` values.

    Validated against ``ExportFormat`` the same way ``ash scan`` validates it, so
    a typo fails immediately with the list of valid formats rather than silently
    producing no report of that kind.
    """
    parsed: List[str] = []
    for item in raw or []:
        for candidate in item.split(","):
            candidate = candidate.strip()
            if not candidate:
                continue
            try:
                parsed.append(ExportFormat(candidate).value)
            except ValueError:
                valid = ", ".join(fmt.value for fmt in ExportFormat)
                raise typer.BadParameter(
                    f"'{candidate}' is not a valid format. Valid formats are: {valid}"
                )
    return parsed


def merge_command(
    results: Annotated[
        List[str],
        typer.Option(
            "--results",
            help=(
                f"A shard's {RESULTS_FILE_NAME}, or a directory containing one. "
                f"Repeat once per shard."
            ),
        ),
    ],
    output_dir: Annotated[
        str,
        typer.Option(
            "--output-dir",
            help="Directory to write the merged results and reports to.",
            envvar="ASH_OUTPUT_DIR",
        ),
    ],
    output_formats: Annotated[
        Optional[List[str]],
        typer.Option(
            "--output-formats",
            help=(
                "Comma-separated report formats to generate. Defaults to the "
                "formats the scan's own configuration asks for."
            ),
        ),
    ] = None,
    config: Annotated[
        Optional[str],
        typer.Option(
            "--config",
            "-c",
            help=(
                "The operator's config file. Its values replace the shards' for "
                "the settings a shard's recorded config cannot choose, such as "
                "where reporters send findings and which off-host reporters run. "
                "Its ash_plugin_modules are the plugin modules the merge loads, "
                "with any --config-overrides adds; a module only the shards "
                "recorded is not loaded. It adds no reporter section the shards "
                "did not record; use --config-overrides for that."
            ),
            envvar="ASH_CONFIG",
        ),
    ] = None,
    config_overrides: Annotated[
        Optional[List[str]],
        typer.Option(
            "--config-overrides",
            help=(
                "Configuration overrides as key-value pairs (e.g., "
                "'reporters.s3.enabled=true'), applied over the shards' recorded "
                "config."
            ),
        ),
    ] = None,
    min_severity: Annotated[
        MinSeverity,
        typer.Option(
            "--min-severity",
            help="Minimum severity that counts as actionable for the exit code.",
            case_sensitive=False,
        ),
    ] = MinSeverity.LOW,
    ignore_suppressions: Annotated[
        bool,
        typer.Option(
            "--ignore-suppressions",
            help=(
                "Ignore all suppression rules and report every finding regardless "
                "of suppression status. Mirrors 'ash scan --ignore-suppressions', "
                "so the same tree gives the same verdict sharded or not."
            ),
        ),
    ] = False,
    fail_on_findings: Annotated[
        Optional[bool],
        typer.Option(
            "--fail-on-findings/--no-fail-on-findings",
            help=(
                "Exit non-zero when the merged report has actionable findings. "
                "Defaults to the scan configuration's value, then to true."
            ),
        ),
    ] = None,
    fail_on_incomplete_scanners: Annotated[
        Optional[bool],
        typer.Option(
            "--fail-on-incomplete-scanners/--no-fail-on-incomplete-scanners",
            help=(
                "Refuse the merge when a shard completed none of the scanners it "
                "owned, and exit 1 when any scanner in the union is ERROR or "
                "MISSING, or when every one is SKIPPED, such as when no selected "
                "scanner had a file to scan. Under "
                "--no-fail-on-incomplete-scanners, a shard whose scanners never ran "
                "contributes no findings and the merged report reads as a "
                "complete, clean scan. Defaults to unset, which prefers the scan "
                "configuration's value and then on; pass "
                "--no-fail-on-incomplete-scanners to merge a partial union anyway."
            ),
        ),
    ] = None,
    log_level: Annotated[
        AshLogLevel, typer.Option("--log-level", help="Set the log level.")
    ] = AshLogLevel.INFO,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    debug: Annotated[
        bool, typer.Option("--debug", "-d", help="Enable debug logging")
    ] = False,
    color: Annotated[bool, typer.Option(help="Enable/disable colorized output")] = True,
):
    """Merge the shard results of a sharded scan into one unified report.

    Each executor of ``ash scan --shard-index k --shard-count n`` writes its own
    results file. This command checks that the shards given reconstruct exactly
    one whole scan, merges them, writes the unified
    ``ash_aggregated_results.json`` and every requested report format, and exits
    with the verdict for the union.

    A shard that owned no failing scanner exits 0, so CI must gate on this
    command and not on per-shard success.
    """
    final_log_level = (
        AshLogLevel.VERBOSE
        if verbose
        else (
            AshLogLevel.DEBUG
            if debug
            else (
                AshLogLevel.ERROR
                if log_level
                in [AshLogLevel.QUIET, AshLogLevel.ERROR, AshLogLevel.SIMPLE]
                else log_level
            )
        )
    )
    logger = get_logger(
        level=logging._nameToLevel.get(final_log_level.value, logging.INFO),
        show_progress=False,
        use_color=color,
    )

    parsed_formats = _parse_output_formats(output_formats)
    overrides = list(config_overrides or [])
    # The verdict settings the command line's flags decide; see VERDICT_FLAGS.
    cli_verdict = {
        "fail_on_findings": fail_on_findings,
        "fail_on_incomplete_scanners": fail_on_incomplete_scanners,
    }

    # The operator's --config, read first and once: a file that does not load
    # refuses the merge with exit 3, as `ash report` refuses it, before any merged
    # results exist and before any shard is read. resolve_operator_config is the
    # one read of the file (a second load here opened it twice); the rest of the
    # merge uses what it returns, as trusted_config below. A path that does not
    # exist, or is not a file, is refused too: the defaults in its place would
    # send the reports somewhere the operator did not choose. Every other error
    # the load can raise arrives as an ASHConfigValidationError
    # (resolve_operator_config wraps OSError, UnicodeDecodeError, ValueError and
    # yaml.YAMLError into ASHConfigSourceError, naming the file once).
    operator_config: Optional[AshConfig] = None
    if config:
        try:
            operator_config = resolve_operator_config(config)
        except ASHConfigValidationError as exc:
            print(_invalid_config_text(exc))
            raise typer.Exit(3)

    # With the other operator-config refusals, before any shard is read:
    # load_plugins imports these modules further down (before anything is
    # written, so a refusal there leaves no merged file either), and a name
    # refused only there would hide behind a shard error the operator fixes
    # first for a merge that is then refused anyway.
    operator_modules = split_plugin_modules(
        getattr(operator_config, "ash_plugin_modules", None) or []
    )
    try:
        refuse_plugin_modules_outside_namespace(
            operator_modules,
            shown=config_module_names(operator_config) if operator_config else None,
        )
    except PluginModuleNamespaceError as exc:
        # In the merge's own closing words: the scan's say nothing was scanned
        # and name options this command does not have.
        message = exc.shown_with(
            "Nothing was imported and nothing was merged. Rename the package or "
            "name the packages inside it, or remove the entry from the --config "
            "file."
        )
        print(f"[red]Refusing to merge: {escape_markup(message)}[/red]")
        raise typer.Exit(3)

    try:
        # The operator's trusted base: the --config read above, or the defaults
        # resolved the way ``ash report`` resolves its config. The overrides are
        # not applied to it here: the confinement below replays them onto it, as
        # resolve_config does for a scan, and applying them twice would repeat an
        # appending override.
        trusted_config = (
            operator_config
            if operator_config is not None
            else resolve_operator_config(config)
        )
        loaded = load_shard_results(results)
        apply_operator_overrides(loaded, overrides)
        # --output-formats names the formats for the merge, so it supplies
        # output_formats where a shard recorded the reference its scan read.
        supply_unread_recorded_fields(
            loaded, trusted_config, overrides, {"output_formats": parsed_formats}
        )
        # Before the completion gate below, which reads one shard's
        # fail_on_incomplete_scanners: shards that disagree on it, or on any other
        # verdict setting, are refused the same way whichever shard that is.
        verify_verdict_settings_agree(
            loaded, cli_verdict, ignore_suppressions=ignore_suppressions
        )
        # Resolved before merging, because the contribution refusal has to happen
        # before a merged report exists on disk. Read from the shard results' own
        # config for the same reason the verdict is: a collector job need not have
        # the source tree checked out, and a config file found on this host could
        # disagree with the one the shards scanned under. The lowest-indexed shard
        # supplies the report's identity elsewhere in this module, so it supplies
        # this too, read in index order rather than --results order.
        require_completion = _resolve_require_scanner_completion(
            _in_index_order(loaded), fail_on_incomplete_scanners
        )
        merged = merge_shard_results(
            loaded, require_scanner_completion=require_completion
        )
        if merged.ash_config is None:
            merged.ash_config = apply_config_overrides(AshConfig(), overrides)
        warn_on_ignored_operator_verdict_settings(
            trusted_config, merged.ash_config, cli_verdict
        )
        # What a config inside the scanned tree may not choose comes from the
        # operator's base instead; see the module docstring.
        confine_recorded_config(
            merged.ash_config, trusted_config, overrides, _base_results_file(loaded)
        )
    except ShardSettingsDisagreeError as exc:
        # On its lines: the shard-disagreement refusal is deliberately
        # multi-line, and the one-line form wrote its breaks as \x0a.
        print(_invalid_config_lines(exc))
        raise typer.Exit(3)
    except ASHConfigValidationError as exc:
        # On one line: every other refusal here can quote a value the operator
        # typed (a --config-overrides entry), and a newline in it must not start
        # a log line of its own.
        print(_invalid_config_text(exc))
        raise typer.Exit(3)
    except ResultsPathError as exc:
        # As Text: the message quotes the operator's path, which can read as
        # markup, and its values are already shown (_refusal_text).
        print(_refusal_text(exc))
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)
    except ShardCoverageError as exc:
        # Printed rather than raised as a traceback: every one of these is an
        # operator-actionable statement about their CI matrix or artifacts, and
        # the message already says what to check. Exit 1 is ASH's "error during
        # execution" code, which is the honest verdict -- the scan's findings are
        # unknown, which is not the same as "no findings".
        print(_refusal_text(exc))
        raise typer.Exit(1)

    # The values the operator's config read from the environment join the
    # shards': the merge redacts its lines and its output with the merged
    # config's values, which were the shards' alone. The operator's config is
    # the one whose !ENV reads this process holds -- the module entry, and any
    # other value a module's import error can quote.
    merged.ash_config._environment_values = _each_value_once(
        getattr(merged.ash_config, "_environment_values", None),
        getattr(trusted_config, "_environment_values", None),
    )

    # Before anything is written, and before the output directory is created. The
    # merged config now names the plugin modules the reports are rendered with,
    # the operator's, and a module outside the plugin namespace, the operator's or
    # one a shard recorded, is refused here as the scan itself refuses it, without
    # importing anything.
    try:
        refuse_plugin_modules_outside_namespace(
            split_plugin_modules(
                getattr(merged.ash_config, "ash_plugin_modules", None) or []
            )
        )
    except PluginModuleError as exc:
        # Escaped: the message quotes the configured name, which may hold markup
        # characters.
        print(f"[red]Invalid configuration: {escape_markup(str(exc))}[/red]")
        raise typer.Exit(3)

    output_dir_path = _relocate_colliding_output_dir(Path(output_dir))
    # The merged results file must not be one of the shard results files it is
    # merged from: an --output-dir that holds a --results file would replace that
    # shard's record with the merged report, and a second merge over the same
    # directory would then read the merged report as one shard of itself.
    overwritten = _results_file_the_merge_would_overwrite(output_dir_path, loaded)
    if overwritten is not None:
        print(
            _refusal_text(
                ResultsPathError(
                    f"--output-dir {_shown(output_dir_path.as_posix())} holds the "
                    f"shard results file {_shown(overwritten.as_posix())} given as "
                    f"--results. Writing the merged {RESULTS_FILE_NAME} there would "
                    f"replace that shard's results with the merged report. Name an "
                    f"output directory that holds no shard's results."
                )
            )
        )
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)
    # The merged results and reports are written into the output directory, so a
    # link there or at reports/ is refused as a scan refuses it.
    try:
        refuse_linked_output_dir(Path.cwd(), output_dir_path)
    except OutputDirLinkRefused as refusal:
        print(f"[red]{escape_markup(str(refusal))}[/red]")
        # 3, as a scan exits for the same refusal (OUTPUT_DIR_REFUSED_EXIT_CODE).
        raise typer.Exit(3)
    # Not created yet: the plugin modules are loaded below, and a module that
    # fails to import refuses the merge, which must leave no output directory
    # either, as the namespace refusal above leaves none. The directory is
    # made at the first write (below).

    # The scan's own configuration, carried through the shard results, rather
    # than a config file resolved on this host. The collector job need not have
    # the source tree checked out at all, and a config file found here could
    # disagree with the one the shards actually scanned under -- which would move
    # the verdict without moving the findings. It was confined above, and the
    # merged results record it as confined.
    plugin_context = PluginContext(
        source_dir=Path.cwd(),
        output_dir=output_dir_path,
        # The name every other component derives for the work directory
        # (core/constants.py), so a reporter or a suppression pass that reads
        # ``work_dir`` finds the merge's where it finds a scan's.
        work_dir=output_dir_path.joinpath(ASH_WORK_DIR_NAME),
        config=merged.ash_config,
        ignore_suppressions=ignore_suppressions,
    )

    # Also before anything is written: a module the operator names that does not
    # import refuses the merge with exit 3, as it refuses a scan. A refused
    # merge leaves no merged results file, rather than one whose metadata
    # records no load error and says nothing about the refusal.
    ash_plugin_manager.set_context(plugin_context)
    try:
        load_plugins(plugin_context=plugin_context)
    except PluginModuleError as exc:
        # A configured module could not be loaded: only knowable by importing,
        # so it fires here rather than beside the name checks above. In the
        # merge's own closing words, with the fix clause following the loss's
        # stage (plugin_module_fix).
        message = exc.shown_with(
            "Nothing was merged and no merged results file was written. "
            f"{plugin_module_fix(exc)}, or remove the entry from the "
            "--config file."
        )
        print(f"[red]Refusing to merge: {escape_markup(message)}[/red]")
        raise typer.Exit(3)
    # Only this merge's reporters: ASH's built-ins and the modules the merged
    # config names (the operator's, confined above). The registry is
    # process-wide, so it can also hold another run's reporters
    # (reporter_classes_for_run).
    reporter_plugins = reporter_classes_for_run(
        split_plugin_modules(
            getattr(merged.ash_config, "ash_plugin_modules", None) or []
        ),
        manager=ash_plugin_manager,
    )
    # The plugin modules are loaded, so the destination options each reporter
    # declares are known. Before the merged results are written, so they record
    # these as confined too.
    confine_declared_reporter_destinations(
        merged.ash_config, reporter_plugins, source=SHARD_RECORDED
    )
    warn_on_unapplied_operator_settings(
        trusted_config, merged.ash_config, reporter_plugins
    )

    merged = apply_aggregated_suppressions(merged, plugin_context)

    # The first write to disk, made only after every refusal has had its say.
    output_dir_path.mkdir(parents=True, exist_ok=True)

    merged_file = output_dir_path.joinpath(RESULTS_FILE_NAME)
    # A results file an earlier run left in a reused output directory goes now,
    # before the report phases, so that no exit from them leaves it behind: a
    # reporter that raises, a cancelled upload or a failed write below would
    # otherwise leave the earlier run's file where a later ``ash report`` reads
    # it as this merge's, and a reporter that reads the output directory while
    # it runs would read it as this merge's results. Removing it only on the path
    # refusal, as before, covered one of those exits. The sentence is kept for the
    # refusal text, which still names what was removed.
    earlier = _remove_an_earlier_results_file(merged_file)
    if earlier:
        logger.info(earlier.strip())
    if merged.ash_config is not None:
        # What the confinement took from the operator's config is recorded as
        # that file wrote it, as a shard records its own
        # (config/environment_record.py). The module list's references were
        # carried with the list, at their indices in the merged list
        # (plugin_module_trust.confine_plugin_modules), so they are not added
        # again here at the operator's indices.
        merged.ash_config._environment_references = (
            *merged.ash_config._environment_references,
            *(
                reference
                for reference in trusted_config._environment_references
                if tuple(reference.path)[:1] != ("ash_plugin_modules",)
            ),
        )
    # The merged results file itself is written after the report phases below,
    # as a scan writes its own after its report phase (interactions/run_ash_scan.py),
    # and after the suppression pass above: written first it described a
    # pre-suppression state while the reports and the exit code described the
    # post-suppression one, and a reporter that refused its paths, or failed,
    # left it behind recording nothing of that. Now such a run leaves none.

    # The plugins were loaded above, before anything was written.
    # A reporter that sends findings off the host runs only when the operator
    # enables it, with --config-overrides. The configuration the shards carried
    # came from whatever config each shard's scan read, a file in the scanned
    # repository included, and the reporter would send the merged findings with
    # this host's credentials; so that configuration decides nothing for it, in
    # either direction. Nor does a config file found on this host. Nor does
    # --config: the shards do not record which tree was scanned, so that file may
    # be the scanned tree's own (a directory beside this one, in no git checkout),
    # and its enabled and destination options for these reporters are replaced
    # with the defaults and the overrides (reporter_trust).
    operator_config = None
    if config or overrides:
        operator_config = apply_config_overrides(
            trusted_config if config else AshConfig(), overrides
        )
        if config:
            from automated_security_helper.config.untrusted_source import (
                MERGE_CONFIG_FILE,
            )

            confine_off_host_reporters_to_overrides(
                operator_config, [Path(config)], overrides, MERGE_CONFIG_FILE
            )
            # The plugin modules are loaded, so the reporters they add are known.
            # One that sends findings off the host and declares no destination
            # options takes its whole section from the defaults and the overrides,
            # as in ash report: the step above marked operator_config for it.
            confine_declared_reporter_destinations(
                operator_config, reporter_plugins, source=MERGE_CONFIG_FILE
            )
    local_reporters, off_host_reporters, notices = select_merge_reporters(
        reporter_plugins,
        shard_config=merged.ash_config,
        operator_config=operator_config,
    )
    for notice in notices:
        logger.warning(notice)
    # Which requested formats an off-host reporter produces. A reporter is
    # selected by its configured name, and the ExportFormat members name the
    # off-host reporters too (aws-security-hub, s3, and the rest), so a
    # --output-formats value can ask for one. The two report phases below split
    # the request between them: the local reporters get the formats they
    # produce, the off-host reporters get theirs, and a phase whose share is
    # empty does not run, as naming only s3 to a scan runs only the s3 reporter.
    requested_formats = set(parsed_formats)
    off_host_format_names = {
        plugin_config_key(reporter_class)
        for reporter_class in reporter_plugins
        if getattr(reporter_class, "sends_off_host", False) is True
    }
    requested_off_host = [f for f in parsed_formats if f in off_host_format_names]
    local_formats = [f for f in parsed_formats if f not in off_host_format_names]
    # An operator section that sets options but no enabled is named when the
    # reporter would otherwise run: with no format requested, or with its own.
    for reporter_class in reporter_plugins:
        if reporter_class in off_host_reporters:
            continue
        if (
            parsed_formats
            and plugin_config_key(reporter_class) not in requested_formats
        ):
            continue
        warn_off_host_section_without_enabled(
            reporter_class, _section(operator_config, reporter_class)
        )

    # ReportPhase writes reports/ash.<extension> for every enabled reporter, and
    # its progress display is used unconditionally, so a display is supplied with
    # output turned off rather than None.
    from automated_security_helper.interactions.run_ash_scan import (
        report_sarif_identity,
    )

    # The output directory may hold an ash.sarif from an earlier run, and the
    # exit-code gate must not read one this merge did not write.
    report_sarif_before = report_sarif_identity(output_dir_path)
    report_phase = ReportPhase(
        plugins=local_reporters,
        plugin_context=plugin_context,
        progress_display=LiveProgressDisplay(show_progress=False),
        asharp_model=merged,
    )
    try:
        # The local phase runs with the formats the local reporters produce; a
        # request that names only off-host formats runs no local reporter, and
        # tells the operator about no format a reporter of the other phase
        # produces. A requested off-host format whose reporter the operator did
        # not enable is run by neither phase, so log_off_host_formats_not_run
        # below says the report phase's line for it.
        if not parsed_formats or local_formats:
            merged = report_phase.execute(
                report_dir=output_dir_path.joinpath("reports"),
                cli_output_formats=local_formats or None,
                aggregated_results=merged,
                python_based_plugins_only=False,
            )
        # The off-host reporters run with the operator's configuration, so their
        # destinations are the operator's too. As in a scan, they run when no
        # format is requested or when --output-formats names one of them. With
        # neither --config nor --config-overrides there is no operator config and
        # every one is refused (select_merge_reporters), so the list is empty
        # then; the None check states that to the type checker. Overrides alone
        # are enough to enable and aim one.
        off_host_to_run = off_host_reporters_to_run(off_host_reporters, operator_config)
        log_off_host_formats_not_run(requested_off_host, off_host_to_run)
        # Only the formats a reporter of this phase produces: the phase accounts
        # for every requested format its reporters do not produce, so a format
        # just named above would be named a second time with another reason, and
        # a request naming only such formats would start a phase that runs nothing.
        off_host_formats = off_host_formats_to_run(requested_off_host, off_host_to_run)
        if off_host_to_run and (not parsed_formats or off_host_formats):
            off_host_context = PluginContext(
                source_dir=Path.cwd(),
                output_dir=output_dir_path,
                work_dir=output_dir_path.joinpath(ASH_WORK_DIR_NAME),
                config=operator_config,
                ignore_suppressions=ignore_suppressions,
            )
            merged = ReportPhase(
                plugins=off_host_to_run,
                plugin_context=off_host_context,
                progress_display=LiveProgressDisplay(show_progress=False),
                asharp_model=merged,
            ).execute(
                report_dir=output_dir_path.joinpath("reports"),
                cli_output_formats=off_host_formats or None,
                aggregated_results=merged,
                python_based_plugins_only=False,
            )
    except ReportPathRefused as exc:
        # Refused before any reporter wrote: a link at the reports directory or at
        # a report file, or a report file name outside it. Printed like the other
        # refusals here, without a traceback. The merged results file is written
        # only below, so a refused merge leaves none of its own; the one an
        # earlier run left in a reused output directory was removed above, or
        # named when it could not be, and the refusal says which.
        print(
            f"[red]Refusing to write reports: {escape_markup(str(exc))} No merged "
            f"{RESULTS_FILE_NAME} was written.{escape_markup(earlier)}[/red]"
        )
        raise typer.Exit(1)

    write_text_atomically(merged_file, merged.model_dump_json(indent=2))
    logger.info(f"Wrote merged results to {merged_file}")

    report_sarif_after = report_sarif_identity(output_dir_path)
    exit_code = _merged_exit_code(
        merged,
        output_dir_path,
        MinSeverity(min_severity).value,
        fail_on_findings,
        fail_on_incomplete_scanners,
        report_sarif_written_this_run=(
            report_sarif_after is not None and report_sarif_after != report_sarif_before
        ),
    )
    _print_merge_summary(merged, merged_file, exit_code)
    if exit_code != 0:
        raise typer.Exit(exit_code)


def _section(config: Optional[AshConfig], reporter_class: type) -> Optional[Any]:
    if config is None:
        return None
    try:
        return config.get_plugin_config(
            plugin_type="reporter", plugin_name=plugin_config_key(reporter_class)
        )
    except Exception:  # noqa: BLE001 -- an unknown reporter has no section
        return None


def off_host_reporters_to_run(
    off_host_reporters: Sequence[Type[ReporterPluginBase[Any]]],
    operator_config: Optional[AshConfig],
) -> List[Type[ReporterPluginBase[Any]]]:
    """The off-host reporters the merge runs, given the operator's configuration.

    An off-host reporter runs with the operator's configuration, so none can run
    without one. :func:`select_merge_reporters` refuses every off-host reporter
    when ``operator_config`` is None, so the list it returns is empty then and
    this returns it unchanged. Should a caller ever hand this a non-empty list
    with no operator configuration, the reporters are not run and the omission is
    said at ERROR, naming them, rather than skipped in silence: a merge whose
    uploads quietly did not happen would read as one that never asked for them.
    """
    if not off_host_reporters or operator_config is not None:
        return list(off_host_reporters)
    names = ", ".join(plugin_config_key(cls) for cls in off_host_reporters)
    ASH_LOGGER.error(
        f"The off-host reporter(s) {names} were selected to run but no operator "
        f"configuration (--config or --config-overrides) was given to run them "
        f"with, so they did not run. This is a defect in the reporter selection: "
        f"report it with the command line used.",
        extra=NO_MARKUP,
    )
    return []


def off_host_formats_to_run(
    requested_off_host: Sequence[str],
    off_host_to_run: Sequence[Type[ReporterPluginBase[Any]]],
) -> List[str]:
    """The requested off-host formats a reporter of the off-host phase produces.

    In request order, once each. A requested format whose reporter the operator
    did not enable is :func:`log_off_host_formats_not_run`'s to name and is left
    out here: the report phase names every requested format its own reporters do
    not produce, so handing it the format would name it a second time, with a
    reason (no such reporter) that is not the merge's. Empty when nothing was
    requested, which leaves the phase to every reporter it was given.
    """
    running = {plugin_config_key(cls) for cls in off_host_to_run}
    return [fmt for fmt in dict.fromkeys(requested_off_host) if fmt in running]


def log_off_host_formats_not_run(
    requested_off_host: Sequence[str],
    off_host_to_run: Sequence[Type[ReporterPluginBase[Any]]],
) -> List[str]:
    """Say which requested off-host formats no report phase of the merge runs.

    ``--output-formats`` can name an off-host reporter's format (``s3``, say). The
    local report phase runs only with the formats the local reporters produce, so
    it never sees such a name, and the off-host phase runs only the reporters the
    operator enabled; a format naming one the operator did not enable would be
    produced by neither phase and, without this, said by neither. The report
    phase tells the operator about every requested format it will not produce
    (``No report will be written for requested format ...``), so this says the
    same line, at the same level, for the formats that fall between the two
    phases, with the merge's own reason: only the operator's overrides turn an
    off-host reporter on. Returns the formats named, in request order, once each.
    """
    running = {plugin_config_key(cls) for cls in off_host_to_run}
    not_run = [fmt for fmt in dict.fromkeys(requested_off_host) if fmt not in running]
    for fmt in not_run:
        ASH_LOGGER.error(
            f"No report will be written for requested format '{fmt}': its reporter "
            f"sends findings off the host and the operator did not enable it for "
            f"this merge. Only --config-overrides reporters.{fmt}.enabled=true turns "
            f"such a reporter on (a --config file's 'enabled' is not read for it), "
            f"so pass that override to get this report.",
            extra=NO_MARKUP,
        )
    return not_run


def select_merge_reporters(
    reporter_classes: Sequence[Type[ReporterPluginBase[Any]]],
    shard_config: Optional[AshConfig],
    operator_config: Optional[AshConfig],
) -> Tuple[
    List[Type[ReporterPluginBase[Any]]], List[Type[ReporterPluginBase[Any]]], List[str]
]:
    """Split ``ash merge``'s reporters into local and off-host ones, and say what was ignored.

    A reporter that sends findings off the host runs only when ``operator_config``
    sets ``enabled: true`` in its section (``off_host_reporter_refused``).
    ``operator_config`` is the operator's ``--config`` with ``--config-overrides``
    applied, after the reporter rule (``reporter_trust``) has replaced what the
    ``--config`` file set for such a reporter, because the shards do not record
    which tree was scanned and the file may be that tree's own. So only the
    overrides turn one on, whatever the reporter's own default for ``enabled`` is:
    a file's ``enabled`` is dropped when no override sets it.
    The configuration the shards recorded is ignored for it, in both directions:
    a shard's ``enabled: true`` does not run it and a shard's ``enabled: false``
    does not stop it. Where the shards' value disagrees with the operator's
    decision, a notice says it was ignored. ``--config-overrides`` are on each
    shard's record before this runs (``apply_operator_overrides``), so a value an
    override sets is the operator's and is not reported. Every recorded
    configuration carries every reporter's ``enabled``, its default included, so a
    value that agrees cannot be told from a default and is not reported.

    Returns the local reporters, the off-host reporters that run, and the notices.
    """
    local: List[Type[ReporterPluginBase[Any]]] = []
    off_host: List[Type[ReporterPluginBase[Any]]] = []
    notices: List[str] = []
    for reporter_class in reporter_classes:
        if getattr(reporter_class, "sends_off_host", False) is not True:
            local.append(reporter_class)
            continue
        name = plugin_config_key(reporter_class)
        refused = off_host_reporter_refused(
            reporter_class, _section(operator_config, reporter_class)
        )
        shard_section = _section(shard_config, reporter_class)
        shard_enabled = (
            shard_section.get("enabled") if isinstance(shard_section, dict) else None
        )
        if isinstance(shard_enabled, bool) and shard_enabled is refused:
            notices.append(
                f"Ignoring 'enabled: {str(shard_enabled).lower()}' for reporter "
                f"'{name}' in the configuration the shards recorded: it sends "
                "findings off the host, so only the operator's --config-overrides "
                f"decide whether it runs. It {'does not run' if refused else 'runs'}."
            )
        if refused:
            continue
        off_host.append(reporter_class)
    return local, off_host, notices


def _relocate_colliding_output_dir(output_dir: Path) -> Path:
    """Move *output_dir* out of the way when it contains the directory being reported on.

    ``ash scan`` has done this for its own ``--output-dir`` since before this command
    existed, and says so loudly (``cli/scan.py``). ``ash merge`` took the operator's
    value verbatim, and it builds its ``PluginContext`` with
    ``source_dir=Path.cwd()``, so ``ash merge --output-dir .`` made the two the same
    directory and ASH wrote its reports into the tree it was treating as the source.

    The consequence is not untidiness. ``utils.sarif_utils.apply_suppressions_to_sarif``
    excludes findings whose location resolves inside ``output_dir`` and outside its
    work directory, on the grounds that those are reports ASH wrote rather than
    findings about the scanned tree. When ``output_dir`` is ``source_dir`` or an
    ancestor of it, that describes every finding: on three shards carrying five
    findings between them, the merged report came out ``Findings: 0 | Actionable: 0``
    at exit 0, which is what a clean scan looks like. To reproduce, disable the
    ancestor guard in ``apply_suppressions_to_sarif`` and run
    ``TestMergeCli::test_an_output_dir_equal_to_the_cwd_is_relocated``. That function
    declines the exclusion in this configuration and says so, and ``ash merge``
    does not apply the exclusion at all (each shard applied its own, see
    :func:`apply_aggregated_suppressions`). Relocating keeps the merge's
    reports out of the directory it treats as the source.

    Equal-to OR an ancestor-of, where ``ash scan`` checks only equality.
    ``--output-dir ..`` from a subdirectory reaches the same state without the paths
    ever being equal, and an ancestor is worse than equality rather than milder.

    Relocated to ``<given>/.ash/ash_output``, the same move and the same subpath
    ``ash scan`` uses, which lands strictly inside the given directory and so is an
    ancestor of nothing. Relocated rather than refused because the operator's intent
    is unambiguous and recoverable -- they wanted the artifacts here -- and a refusal
    would fail a pipeline over a path choice.

    Args:
        output_dir: The ``--output-dir`` value as given.

    Returns:
        The directory to write to: *output_dir* unchanged in the ordinary case.
    """
    resolved = output_dir.resolve()
    cwd = Path.cwd().resolve()
    # is_relative_to is true for equal paths, so this covers the collision case as
    # well as containment.
    if not cwd.is_relative_to(resolved):
        return output_dir

    relocated = output_dir.joinpath(".ash", "ash_output")
    # Checked again, not assumed: a working directory inside the relocated path
    # (``ash merge --output-dir ../..`` from within a previous relocation) still
    # has it as an ancestor, and the relocation then changed nothing but the
    # message. Each step lands strictly inside the previous one only without
    # links: a committed ``.ash/ash_output -> ..`` resolves every step back to
    # the working directory, and a loop that read only the ancestor test never
    # returned. So a step that does not resolve strictly deeper than the last
    # ends the loop, and the link at the relocated path is left to
    # refuse_linked_output_dir, which refuses it as any link there.
    previous = resolved
    while True:
        deeper = relocated.resolve()
        if not cwd.is_relative_to(deeper):
            break
        if deeper == previous or not deeper.is_relative_to(previous):
            break
        previous = deeper
        relocated = relocated.joinpath(".ash", "ash_output")
    print(
        f"[bold yellow]output-dir has been adjusted to the following to avoid "
        f"collisions and potential impact to the reported tree: "
        f"{escape_markup(Path(relocated).as_posix())}[/bold yellow]"
    )
    return relocated


def _remove_an_earlier_results_file(merged_file: Path) -> str:
    """Remove a results file an earlier run left at *merged_file*; say what happened.

    Called once the output directory exists and before the report phases, when
    this run has written no results file of its own, so that no exit from those
    phases leaves the file behind. A file from an earlier run in a reused output
    directory would otherwise be read by a later ``ash report`` as this merge's
    (the write-then-remove order this replaced removed it as a side effect).
    Returns the sentence the log and a refusal text use: empty when there was no
    file; a file that cannot be removed is named rather than raised over, so a
    refusal is still printed as a refusal and the merge still runs.
    """
    if not merged_file.exists():
        return ""
    try:
        merged_file.unlink()
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        return (
            f" An earlier run's {RESULTS_FILE_NAME} at {merged_file.as_posix()} "
            f"could not be removed ({reason}); it is not this merge's."
        )
    return (
        f" An earlier run's {RESULTS_FILE_NAME} at {merged_file.as_posix()} was "
        "removed."
    )


def _results_file_the_merge_would_overwrite(
    output_dir: Path, loaded: Sequence[Tuple[Path, AshAggregatedResults]]
) -> Optional[Path]:
    """The ``--results`` file the merged results file would replace, if any.

    Compared as the file system identifies a file (``os.path.samefile``: device
    and inode, or the handle on Windows), so the same file named two ways, a
    hard link to it, and a spelling that differs only in case on a file system
    that ignores case are all caught; comparing resolved path text missed the
    last two. A results directory given as ``--results`` is compared by the
    file inside it. None when nothing is at the output path yet (no file can be
    the same as a file that does not exist) or when the output directory holds
    no shard's results file.
    """
    target = output_dir.joinpath(RESULTS_FILE_NAME)
    if not target.exists():
        return None
    for results_file, _ in loaded:
        try:
            if os.path.samefile(target, results_file):
                return results_file
        except OSError:
            continue
    return None


def _resolve_require_scanner_completion(
    loaded: Sequence[Tuple[Path, AshAggregatedResults]],
    cli_value: Optional[bool],
) -> bool:
    """Whether to refuse a merge whose shards completed nothing.

    The CLI flag wins; otherwise the scan's own ``fail_on_incomplete_scanners``,
    carried in the shard results; otherwise on, matching
    ``AshConfig.fail_on_incomplete_scanners``. The same precedence
    ``fail_on_findings`` follows, so an operator does not have to remember which
    of the two knobs reads the config first.

    The final fallback agrees with the model default, and that is the whole rule --
    it tracks the model rather than holding an opinion of its own. It has now read
    both values, and each time it had to move with the model: a merge that gated by
    default while a scan of the same tree did not would mean the same shards passed
    or failed depending on which command looked at them.
    ``tests/unit/cli/test_merge.py::TestRequireScannerCompletionResolution`` asserts
    the two are equal rather than asserting either value, so it catches a change to
    one without the other in either direction.

    Called before coverage has been verified, with the shards in index order
    (:func:`_in_index_order`), so the first that carries a config is the
    lowest-indexed shard's, whose config the merged report keeps. Shards that
    disagree on this setting are refused before this is called
    (:func:`verify_verdict_settings_agree`), unless the flag decides it.
    """
    if cli_value is not None:
        return cli_value
    for _, results in loaded:
        value = getattr(results.ash_config, "fail_on_incomplete_scanners", None)
        if isinstance(value, bool):
            return value
    return True


def _merged_exit_code(
    merged: AshAggregatedResults,
    output_dir: Path,
    min_severity: str,
    fail_on_findings: Optional[bool],
    fail_on_incomplete_scanners: Optional[bool] = None,
    report_sarif_written_this_run: Optional[bool] = None,
) -> int:
    """Compute the verdict for the union using the scan's own exit-code rules.

    Delegates to ``run_ash_scan._compute_exit_code`` rather than re-deriving the
    severity tables. Those tables were duplicated once already, which is why
    ``utils/severity_ladder.py`` exists; a third copy here would let ``ash merge``
    and ``ash scan`` disagree about the same findings, and the disagreement would
    only show up as a CI job that passes when it should fail.

    Called after the report phase because ``_compute_exit_code`` reads
    ``reports/ash.sarif`` to apply ``severity_threshold``, and that file is
    written by the SARIF reporter. When no SARIF report was requested it falls
    back to the in-memory unified metrics -- the same fallback a single scan with
    the SARIF reporter disabled takes, so parity holds either way.

    Delegating also means the completeness gate is inherited rather than
    reimplemented. It answers a narrower question than the pre-merge contribution
    refusal: a shard that ran two of its three scanners contributed something, so
    it is not refused, but the union is still short one scanner and this reports
    it.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    options = ScanOptions(
        source_dir=Path.cwd(),
        output_dir=output_dir,
        min_severity=min_severity,
        fail_on_findings=fail_on_findings,
        fail_on_incomplete_scanners=fail_on_incomplete_scanners,
        show_summary=False,
        progress=False,
    )
    config_fail_on_findings = getattr(merged.ash_config, "fail_on_findings", None)
    config_fail_on_incomplete = getattr(
        merged.ash_config, "fail_on_incomplete_scanners", None
    )
    return _compute_exit_code(
        merged,
        options,
        config_fail_on_findings,
        config_fail_on_incomplete,
        report_sarif_written_this_run=report_sarif_written_this_run,
    )


def _print_merge_summary(
    merged: AshAggregatedResults, merged_file: Path, exit_code: int
) -> None:
    """Report what was merged and what the union's verdict is."""
    stats = merged.metadata.summary_stats
    indices = getattr(merged.metadata, MERGED_SHARD_INDICES_KEY, []) or []
    count = getattr(merged.metadata, MERGED_SHARD_COUNT_KEY, len(indices))

    print(
        f"\n[cyan]=== ASH Merge: {len(indices)} of {count} shards recombined ===[/cyan]"
    )
    print(f"Merged results: {escape_markup(merged_file.as_posix())}")
    print(
        f"Scanners: {len(merged.scanner_results)} | "
        f"Findings: {stats.total} | Actionable: {stats.actionable} | "
        f"Suppressed: {stats.suppressed}"
    )
    if exit_code == 2:
        print(
            f"[bold red]ERROR (2) Exiting due to {stats.actionable} actionable "
            f"findings across the merged shards[/bold red]"
        )
    elif exit_code == 1:
        # Reached when the union carries an ERROR or MISSING scanner but no shard
        # was empty enough to be refused outright. Naming the scanners matters
        # more here than in a single scan: the operator has n CI jobs and no other
        # way to tell which one to look at.
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
            incomplete_scanners,
        )

        incomplete = incomplete_scanners(merged)
        if incomplete:
            # "did not complete" reads as "never ran", which is only one of the two
            # cases this list now carries: a scanner that evaluated some of its
            # targets and not others also lands here, with its counts in the status
            # string. Distinct from _completed() above, which still asks the
            # narrower did-it-run-at-all question that shard refusal depends on.
            print(
                f"[bold red]ERROR (1) Exiting because {len(incomplete)} scanner(s) "
                f"in the merged scan did not evaluate everything they were given"
                f"[/bold red]"
            )
            # The names are the shards': shown, and the line broken where one
            # starts it with "::". Printed as Text, once shown: escape_markup
            # shows a value's controls itself, and run over shown text it doubled
            # each escape's backslash.
            for name, status in incomplete:
                line = _shown_lines(f"  {_shown(name)}: {_shown(status)}")
                print(Text(line, style="red"))
        # _merged_exit_code counts these too, so the summary names them: a
        # merge that fails for an archive over a limit or one that could not be
        # read otherwise prints only the counts. Their reasons hold file names
        # from the scanned tree, so they are printed as inert text.
        converters = incomplete_converters(merged)
        if converters:
            print(
                f"[bold red]ERROR (1) Exiting because conversion in the merged scan "
                f"was incomplete: {len(converters)} converter(s) did not process "
                f"the files they were given[/bold red]"
            )
            # A row is (name, reason, kinds): read by field, not unpacked. Shown
            # and printed as Text, as the scanner lines above are.
            for row in converters:
                line = _shown_lines(f"  {_shown(row.name)}: {_shown(row.reason)}")
                print(Text(line, style="red"))
