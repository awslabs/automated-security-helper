# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Hold every scanner content database to its declared age bound at scan time.

Why this exists
---------------
A security scanner run against a stale database returns a result that looks exactly like a
clean one. Measured with grype v0.111.0 under ASH's offline settings: a database built 10 days
earlier scanned with exit 0 and no warning, and ASH's own offline validator called it "0 days
old" because it read the file's mtime rather than the database's build time. trivy's
``--skip-db-update`` does the same, and the offline semgrep and opengrep rulesets never aged
out at all. Online, grype and trivy refresh a stale database themselves and fail loudly when
they cannot; offline nothing did.

So after each scanner that reads a database declared in ``utils/content_databases.py``, this
module reads the database's OWN build timestamp, the same way in online and offline mode, and
compares it to the declared ``max_age``. Measuring after the scan rather than before is
deliberate: online, the tool may have just refreshed the database, and the copy it scanned
with is the one on disk afterwards. Measuring before would fail scans the tool was about to
fix.

What a stale database does
--------------------------
Decided per scan by ``content_db_staleness`` (``--allow-stale-content-db`` on the CLI):

* ``fail`` (the default): the scanner's findings are kept, and the scan exits 1 with a message
  naming the database, its build time, its age, the bound, and how to refresh or opt out.
* ``warn``: the scan proceeds, and the same message goes to the log AND into the reports, so a
  reader of a report can see the scan ran against a stale database.

``content_db_staleness_overrides`` narrows that to one database: an entry names a database, a
policy, and a required expiration date, and holds only that database to its own policy until
00:00 UTC on that date. It exists for an upstream publisher that has stopped publishing for a
few days, where ``warn`` for the whole scan would also stop failing on every other database.
An expired entry is ignored with a warning, so the database returns to the policy it has
without the entry (the scan-wide policy, or for trivy-db the offline image's default described
below) without anyone having to remember to remove it. Either form of ``--allow-stale-content-db``
clears the list for its scan (``content_db_staleness_flag_overrides``), so the flag still
decides for every database.

An image built with ``OFFLINE=YES`` holds trivy-db to ``warn`` by default rather than to
``content_db_staleness: fail`` (``OFFLINE_IMAGE_POLICIES`` in ``utils/content_databases.py``,
which also says why only trivy-db). The image's own environment turns it on
(``OFFLINE_IMAGE_ENV``), never the config, which can only turn it off
(``content_db_staleness_offline_image_default: false``). A ``content_db_staleness_overrides``
entry for trivy-db outranks it, an expired one falls back to it, and either form of
``--allow-stale-content-db`` turns it off for its scan. The record's ``policy_source`` says it
chose the policy, so every report that shows the warning says why the scan still passed.

Where the fact is recorded, and why there
-----------------------------------------
On the scanner's SARIF invocation, as a ``toolConfigurationNotifications`` entry whose
descriptor id is ``STALE_NOTIFICATION_ID``, at level ``error`` under ``fail`` and ``warning``
under ``warn``. Every measurement, fresh or stale, also goes into the invocation's property bag
under ``INVOCATION_PROPERTY``. The invocation rather than the run's own property bag because
``SarifReport.merge_sarif_report`` keeps only the first scanner's run-level properties and
extends invocations, so a run property would vanish from ``ash.sarif`` for every scanner but
one. The exit-code gate, the reports and ``ash merge`` all read it back from there, so the
decision travels with the results: a container-mode scan's host reads it out of
``ash_aggregated_results.json``, and a merged shard keeps the policy its own scan ran under.

A configuration notification rather than an execution one, because
``run_ash_scan.unevaluated_rules`` treats every error-level ``toolExecutionNotifications``
entry as a rule that could not run, and a stale database is not that. It is a fact about the
tool's input, which is what SARIF's configuration notifications describe.

Failure modes
-------------
* A build time that cannot be read (the tool printed nothing parseable, the metadata is
  missing) counts as stale, with the reason in the message. An unmeasurable database is not
  evidence of a fresh one, and treating it as fresh would reopen the silent case. So does a
  build time further in the future than ``CLOCK_SKEW_ALLOWANCE``: its age would be
  negative, inside every bound, so it is not a measurement either.
* A database the tool reports does not exist at all is ``absent``, which is more than
  stale: the scanner had nothing to match against, so the executor records it ERROR
  whatever the policy says. ``warn`` relaxes the age bound for a database that exists.
* The offline rulesets carry no build time of their own. The Dockerfile records the download
  time in ``RULESET_FETCHED_AT_FILE``; without it the oldest rules file's mtime is used, which
  an ordinary ``cp`` resets to the copy time and so can only under-state the age. The record
  says which source it used.
* Only scanners that return a SARIF report are measured. A scanner that failed outright is
  already reported as ERROR or MISSING, and its database contributed nothing.

What the probes read
--------------------
grype's and trivy's probes read the cache the scan read, and nothing the scanned
repository wrote. Measured with trivy 0.75.0 and grype 0.120.1: run from a directory
holding a ``trivy.yaml`` with ``cache.dir`` (or a ``.grype.yaml`` or
``.grype/config.yaml`` with ``db.cache-dir``) naming a planted database, ``trivy version``
and ``grype db status`` reported the planted database's time (2099-01-01), so a
repository scanned with ``cd repo && ash --offline`` could carry a stale database past
this check. So each probe runs from ``ProbeContext.cwd``, outside the scanned tree, passes
``content_db_shared.EMPTY_TOOL_CONFIG`` as its config file, the one the refresh passes
when the caller gives it no operator config of its own (neither tool then looks for
one), and names ``ProbeContext.cache_dir``, the directory the scanner pointed its scan at,
with the flag or variable that beats any config file (``--cache-dir``,
``GRYPE_DB_CACHE_DIR``).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from automated_security_helper.utils.content_databases import (
    CONTENT_DATABASES,
    DEFAULT_STALENESS_POLICY,
    OFFLINE_IMAGE_POLICIES,
    RULESET_FETCHED_AT_FILE,
    STALENESS_FAIL,
    STALENESS_POLICIES,
    STALENESS_WARN,
    ContentDatabase,
    built_offline,
    go_duration,
    is_future_dated,
    is_stale,
    parse_timestamp,
)
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.output_excerpt import (
    head_and_tail,
    tool_output_excerpt,
)
from automated_security_helper.utils.subprocess_utils import spawn_run
from automated_security_helper.utils.process_env import snapshot_environ

if TYPE_CHECKING:
    from automated_security_helper.schemas.sarif_schema_model import Notification

STALE_NOTIFICATION_ID = "ASH-CONTENT-DB-STALE"


class ContentDatabaseAbsent(ValueError):
    """The tool reports that the database does not exist, not only that it is unread."""


INVOCATION_PROPERTY = "ash_content_databases"
#: The longest text ``parse_timestamp`` is given from a file ASH reads a build or
#: download time out of: an RFC 3339 timestamp with nanoseconds and an offset is
#: 35 characters.
_TIMESTAMP_TEXT_LIMIT = 64
OPT_OUT_HINT = (
    "To scan against it anyway, pass --allow-stale-content-db or set "
    "`content_db_staleness: warn` in the ASH config."
)
_PROBE_TIMEOUT_SECONDS = 60
#: How the unset time value of grype's own language is written in JSON (year 1).
_ZERO_TIME_PREFIX = "0001-01-01"


@dataclass
class ContentDbAgeRecord:
    """One measurement of one content database, as reported."""

    name: str
    scanner: str
    built: Optional[datetime]
    measured_by: str
    max_age: timedelta
    measured_at: datetime
    policy: str
    bound_source: str
    bound_is_tool_default: bool
    refresh: str
    error: Optional[str] = None
    timestamp_label: str = "built"
    #: Set when a ``content_db_staleness_overrides`` entry chose ``policy`` rather than
    #: ``content_db_staleness``: says which entry, and until when. Or, set to
    #: ``offline_image_policy_source(name)``, when the offline image's default did. Omitted from
    #: ``to_dict`` when unset, so a scan with no overrides records exactly what it did
    #: before the field existed.
    policy_source: Optional[str] = None
    #: The tool reports that the database does not exist (see "Failure modes" in the
    #: module docstring). Omitted from ``to_dict`` when False, like ``policy_source``.
    absent: bool = False
    #: What the scan that made this record decided about ``stale``, when the record
    #: was read back from a results file (``from_dict``); None for a record this
    #: process measured. A read-back record keeps the scan's decision: recomputed from
    #: ``built`` and ``measured_at`` as the file carries them, truncated to the second,
    #: and from the reading ASH's bound rather than the recorded one, the answer could
    #: differ at the edge, and an error-level notification then read back as not
    #: enforced and left the exit-code gate.
    recorded_stale: Optional[bool] = None
    #: The age the scan measured, in whole seconds, when the record was read back from
    #: a results file (``age_seconds``); None for a record this process measured. The
    #: file's timestamps are written to the second, so an age recomputed from them can
    #: differ from the scan's by up to a second, and at the bound that read as "past
    #: its bound" beside an age equal to the bound. The recorded age keeps ``age`` and
    #: the message consistent with the recorded decision.
    recorded_age_seconds: Optional[int] = None

    @property
    def age(self) -> Optional[timedelta]:
        if self.recorded_age_seconds is not None:
            return timedelta(seconds=self.recorded_age_seconds)
        if self.built is None:
            return None
        return self.measured_at - self.built

    @property
    def stale(self) -> bool:
        """Past the bound, or of unknown age; see "Failure modes" in the module docstring.

        Measured against the bound this record carries (``max_age``), which is the
        bound the scan held the database to: a record read back from an older results
        file keeps its own answer when this ASH declares another bound.
        """
        if self.recorded_stale is not None:
            return self.recorded_stale
        if self.built is None:
            return True
        return is_stale(_recorded_bound(self), self.built, self.measured_at)

    @property
    def enforced(self) -> bool:
        """Whether this record fails the scan: stale, under the ``fail`` policy."""
        return self.stale and self.policy == STALENESS_FAIL

    def message(self) -> str:
        if self.absent:
            return (
                f"Content database {self.name} ({self.scanner}) does not exist "
                f"({self.error or 'the tool reports no database'}). The scanner had "
                "nothing to match against, so it is recorded ERROR whatever "
                f"content_db_staleness says. To create it, {self.refresh}."
            )
        bound = go_duration(self.max_age)
        whose = (
            f"{self.scanner}'s own bound"
            if self.bound_is_tool_default
            else "ASH's bound"
        )
        if self.built is None:
            head = (
                f"Content database {self.name} ({self.scanner}): the time it was "
                f"{self.timestamp_label} could not be read ({self.error or 'no timestamp'}), "
                f"so it cannot be shown to be inside its {bound} bound ({whose})."
            )
        elif is_future_dated(self.built, self.measured_at):
            ahead = self.built - self.measured_at
            ahead_text = (
                format_age(ahead)
                if ahead >= timedelta(hours=1)
                else f"{int(ahead.total_seconds() // 60)}m"
            )
            head = (
                f"Content database {self.name} ({self.scanner}): the time it says it was "
                f"{self.timestamp_label}, {_iso(self.built)}, is {ahead_text} ahead of this "
                "host's clock "
                f"(read from {self.measured_by}), so its age cannot be measured and it "
                f"cannot be shown to be inside its {bound} bound ({whose})."
            )
        else:
            head = (
                f"Content database {self.name} ({self.scanner}) is stale: "
                f"{self.timestamp_label} {_iso(self.built)}, {format_age(self.age)} old, "
                f"past its {bound} bound ({whose}); age read from {self.measured_by}."
            )
        if self.policy == STALENESS_FAIL:
            consequence = (
                "The scan fails: a clean result from a stale database is not evidence of a "
                "clean target."
            )
            if self.policy_source:
                # An override entry holds this database to fail: the scan-wide
                # setting the hint names may already be warn, and changes
                # nothing for it. The entry is what to change, or the flag,
                # which outranks every override entry for its one scan
                # (content_databases.content_db_staleness_flag_overrides).
                tail = (
                    f"To refresh it, {self.refresh}. It is held to fail by the "
                    f"{self.policy_source}; to scan against it anyway, pass "
                    "--allow-stale-content-db (it outranks the entry for that scan), "
                    "or change that entry's policy to warn or remove it from the "
                    "ASH config."
                )
            else:
                tail = f"To refresh it, {self.refresh}. {OPT_OUT_HINT}"
        else:
            because = (
                f"the {self.policy_source} sets it to warn"
                if self.policy_source
                else "content_db_staleness is warn"
            )
            consequence = (
                f"The scan ran against it anyway because {because}, so "
                "it may be missing advisories or rules published since."
            )
            tail = f"To refresh it, {self.refresh}."
            if self.policy_source == offline_image_policy_source(self.name):
                tail = (
                    "To refresh it, rebuild the image (`ash build-image --offline`), "
                    f"or {self.refresh}."
                )
        return f"{head} {consequence} {tail}"

    def to_dict(self) -> Dict[str, Any]:
        age = self.age
        return {
            "name": self.name,
            "scanner": self.scanner,
            "built": _iso(self.built) if self.built else None,
            "age_seconds": int(age.total_seconds()) if age is not None else None,
            "age": format_age(age) if age is not None else None,
            "max_age": go_duration(self.max_age),
            "max_age_seconds": int(self.max_age.total_seconds()),
            "stale": self.stale,
            "policy": self.policy,
            "enforced": self.enforced,
            "measured_by": self.measured_by,
            "measured_at": _iso(self.measured_at),
            "bound_source": self.bound_source,
            "bound_is_tool_default": self.bound_is_tool_default,
            "refresh": self.refresh,
            "error": self.error,
            "timestamp_label": self.timestamp_label,
            **({"policy_source": self.policy_source} if self.policy_source else {}),
            **({"absent": True} if self.absent else {}),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ContentDbAgeRecord":
        built = data.get("built")
        return cls(
            name=str(data.get("name", "")),
            scanner=str(data.get("scanner", "")),
            built=parse_timestamp(built) if built else None,
            measured_by=str(data.get("measured_by", "")),
            max_age=timedelta(seconds=int(data.get("max_age_seconds", 0) or 0)),
            measured_at=parse_timestamp(str(data["measured_at"])),
            policy=str(data.get("policy", DEFAULT_STALENESS_POLICY)),
            bound_source=str(data.get("bound_source", "")),
            bound_is_tool_default=bool(data.get("bound_is_tool_default", False)),
            refresh=str(data.get("refresh", "")),
            error=data.get("error"),
            timestamp_label=str(data.get("timestamp_label") or "built"),
            policy_source=data.get("policy_source") or None,
            absent=data.get("absent") is True,
            # The scan's own decision, kept as it was written; a file from before
            # the field was written (no boolean) is measured from its timestamps.
            recorded_stale=(
                data["stale"] if isinstance(data.get("stale"), bool) else None
            ),
            # The scan's own age, so the read-back age and message agree with its
            # decision rather than with second-truncated timestamps.
            recorded_age_seconds=(
                data["age_seconds"]
                if isinstance(data.get("age_seconds"), int)
                and not isinstance(data.get("age_seconds"), bool)
                else None
            ),
        )


def _recorded_bound(record: "ContentDbAgeRecord") -> ContentDatabase:
    """A registry stand-in carrying the bound the record was measured against.

    ``is_stale`` reads only the entry's ``max_age``. The record's own bound, not the
    registry's for a database of that name: a record read back from a results file
    written under another bound (an older ASH, or one this ASH no longer declares)
    is judged by the bound its scan held the database to.
    """
    return ContentDatabase(
        name=record.name,
        scanner="",
        cache_path="",
        max_age=record.max_age,
        bound_source="",
        bound_is_tool_default=False,
        age_source="",
        refresh="",
    )


def _iso(value: datetime) -> str:
    # isoformat rather than strftime: on glibc ``%Y`` writes a year under 1000 without
    # zero padding ("1-01-01" for Go's zero time), which ``parse_timestamp`` cannot
    # read back, so such a record vanished from every read-back of the results.
    try:
        value = value.astimezone(timezone.utc)
    except (OverflowError, ValueError, OSError):
        # A time at the edge of datetime's range with a non-UTC offset: the
        # conversion leaves the range. Written with its own offset instead, which
        # parse_timestamp reads back; raised, it broke the "never raises" callers
        # (measure, assess_scanner) that quote the time in a message.
        pass
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def format_age(age: Optional[timedelta]) -> str:
    """``10d 3h`` for ten days and three hours; ``5h`` under a day."""
    if age is None:
        return "unknown"
    total_hours = int(age.total_seconds() // 3600)
    days, hours = divmod(max(total_hours, 0), 24)
    return f"{days}d {hours}h" if days else f"{hours}h"


def resolve_policy(config: Any) -> str:
    """The staleness policy a scan runs under: the config field when valid, else ``fail``.

    The CLI flag reaches here as a config override (``content_db_staleness=warn``), the same
    way ``--compact-report`` does, so this one read covers local, container, nix and workspace
    mode alike.
    """
    value = getattr(config, "content_db_staleness", None)
    value = getattr(value, "value", value)
    if isinstance(value, str) and value.lower() in STALENESS_POLICIES:
        return value.lower()
    return DEFAULT_STALENESS_POLICY


def resolve_overrides(config: Any) -> List[Any]:
    """The config's ``content_db_staleness_overrides`` entries, expired ones included.

    Expiry is decided in ``assess_scanner``, against the same clock as the measurement,
    so that an expired entry is reported once per database it would have applied to.
    """
    return list(getattr(config, "content_db_staleness_overrides", None) or [])


def resolve_offline_image_default(
    config: Any, environ: Optional[Mapping[str, str]] = None
) -> bool:
    """Whether ``OFFLINE_IMAGE_POLICIES`` applies to this scan.

    Only where ``environ`` (the process's own environment by default) has
    ``OFFLINE_IMAGE_ENV`` set to YES, which an image built with ``OFFLINE=YES`` does,
    and only while the config's ``content_db_staleness_offline_image_default`` is left
    true. So a config can turn it off, never on: without the variable it is off
    whatever the config says.
    """
    # A locked copy, not the live mapping (utils/process_env.py).
    if not built_offline(snapshot_environ() if environ is None else environ):
        return False
    return (
        getattr(config, "content_db_staleness_offline_image_default", True) is not False
    )


def offline_image_policy_source(name: str) -> str:
    """The ``policy_source`` of a record whose policy the offline image's default chose."""
    return f"default for {name} in an image built with OFFLINE=YES"


def _default_policy_for(
    entry: ContentDatabase, policy: str, offline_image: bool
) -> tuple[str, Optional[str]]:
    """The policy a database is held to when no override entry names it, and why."""
    image_policy = OFFLINE_IMAGE_POLICIES.get(entry.name) if offline_image else None
    if policy == STALENESS_FAIL and image_policy in STALENESS_POLICIES:
        return str(image_policy), offline_image_policy_source(entry.name)
    return policy, None


def _policy_for(
    entry: ContentDatabase,
    policy: str,
    overrides: Sequence[Any],
    now: datetime,
    offline_image: bool = False,
) -> tuple[str, Optional[str]]:
    """The policy one database is held to, and which override or default chose it, if any."""
    default, default_source = _default_policy_for(entry, policy, offline_image)
    held_to = (
        f"{default}, the {default_source}"
        if default_source
        else f"content_db_staleness ({policy})"
    )
    for override in overrides:
        if getattr(override, "database", None) != entry.name:
            continue
        expires = _iso(override.expires_at)
        if override.is_expired(now):
            ASH_LOGGER.warning(
                f"The content_db_staleness_overrides entry for {entry.name} expired at "
                f"{expires} and is ignored; {entry.name} is held to {held_to}. "
                "Remove the entry from the ASH config."
            )
            break
        chosen = str(getattr(override.policy, "value", override.policy)).lower()
        if chosen not in STALENESS_POLICIES:
            break
        # The reason is a config field, which an operator can fill from the
        # environment: escapes removed, controls escaped, cut to a line's worth.
        reason = tool_output_excerpt(str(override.reason), 300)
        ASH_LOGGER.info(
            f"Content database {entry.name} is held to {chosen} rather than "
            f"{held_to} by a content_db_staleness_overrides entry until {expires}: "
            f"{reason}"
        )
        return chosen, (
            f"content_db_staleness_overrides entry for {entry.name}, which expires at "
            f"{expires}"
        )
    if default_source:
        ASH_LOGGER.info(
            f"Content database {entry.name} is held to {default} rather than "
            f"content_db_staleness ({policy}): it is the {default_source}."
        )
    return default, default_source


# --------------------------------------------------------------------------- measurement


@dataclass
class ProbeContext:
    """What a measurer needs from the scanner that used the database.

    ``values`` are the scanner's env-read values: a probe's output excerpt is
    redacted with them BEFORE it is cut, so a cut cannot split a value and
    leave a fragment the downstream whole-spelling redaction misses.
    """

    env: Dict[str, str]
    executable: Optional[str] = None
    #: The database's directory as the scan used it: grype's and trivy's cache
    #: (``content_db_refresh.default_cache_dir``), or the offline rules directory.
    #: For grype and trivy, None leaves the choice to the tool, with ``env``.
    cache_dir: Optional[str] = None
    #: The config file the scan passed the tool, so a probe reads the database
    #: through the same settings; None means ``EMPTY_TOOL_CONFIG`` (trivy only).
    config_file: Optional[str] = None
    #: Where a probe runs: outside the scanned tree
    #: (``path_trust.cwd_outside_scanned_tree``). None runs it from the filesystem
    #: root of the temporary directory, which no repository writes.
    cwd: Optional[str] = None
    #: The caller's env-read values: a probe's output quoted in an error is
    #: redacted with them before it is cut.
    values: Tuple[str, ...] = ()


def _probe_cwd(ctx: ProbeContext) -> str:
    if ctx.cwd:
        return ctx.cwd
    import tempfile

    return Path(os.path.abspath(tempfile.gettempdir())).anchor


def _run_json(
    command: List[str],
    env: Mapping[str, str],
    *,
    ctx: ProbeContext,
) -> Any:
    """Run a tool's status command and parse its stdout as JSON, whatever it exits with.

    ``grype db status`` exits 1 when it considers the database invalid -- including when it
    is merely past grype's own bound -- and still prints the JSON with ``built`` in it.

    The probe runs in the directory *ctx* declares (:func:`_probe_cwd`), and an
    excerpt of what it printed is redacted with ``ctx.values`` before it is cut. There
    is no parameter for another working directory: a caller cannot run a probe in a
    directory its context did not declare, which is the one outside the scanned tree
    (``ProbeContext.cwd``). Everything after ``env`` is keyword-only, so a path passed
    in the third position is refused instead of run in.
    """
    values = ctx.values
    proc = spawn_run(  # nosec B603 - resolved tool binary, list arguments
        command,
        capture_output=True,
        text=True,
        # Replacement, not the strict default: a byte the locale encoding does
        # not read in the probe's output is a probe that failed to parse (a
        # record of unknown age), not a UnicodeDecodeError out of the measurer.
        errors="replace",
        env=dict(env),
        cwd=_probe_cwd(ctx),
        timeout=_PROBE_TIMEOUT_SECONDS,
        check=False,
    )
    text = (proc.stdout or "").strip()
    if not text:
        from automated_security_helper.utils.error_text import shown_tool_stderr

        # REDACTED BEFORE the excerpt is cut: a cut can split an env-read
        # value, and the downstream whole-spelling redaction cannot match
        # the fragment.
        shown = shown_tool_stderr((proc.stderr or "").strip(), values)
        raise ValueError(
            f"`{' '.join(command)}` printed nothing (exit {proc.returncode}): "
            f"{head_and_tail(shown, 300)}"
        )
    return json.loads(text)


def _built_from_grype(ctx: ProbeContext) -> tuple[datetime, str]:
    if not ctx.executable:
        raise ValueError("grype executable not found")
    env = dict(ctx.env)
    if ctx.cache_dir:
        env["GRYPE_DB_CACHE_DIR"] = ctx.cache_dir
    status = _run_json(
        [
            ctx.executable,
            "db",
            "status",
            "-o",
            "json",
            "-c",
            EMPTY_TOOL_CONFIG.as_posix(),
        ],
        env,
        ctx=ctx,
    )
    built = status.get("built") if isinstance(status, dict) else None
    error = str(status.get("error") or "") if isinstance(status, dict) else ""
    path = status.get("path") if isinstance(status, dict) else None
    if isinstance(built, str) and built.startswith(_ZERO_TIME_PREFIX):
        # grype's unset time value (a status document for a database it could not
        # read) is a non-empty string, so it passed the truthiness tests below
        # as a build time and was graded stale instead of absent or unknown.
        built = None
    # grype's own word of absence comes first, whatever ``built`` says: a
    # status document for a database that does not exist can still carry a
    # zero-time ``built``, which read as a build time graded merely stale,
    # under a policy warn can relax. The path alone decides nothing while
    # ``built`` is given: grype answers from its own cache directory, which
    # this process need not be able to see (another user's, a container's),
    # and a stale database reports its path with an age error, not absence.
    if "does not exist" in error or (
        not built and isinstance(path, str) and path and not Path(path).exists()
    ):
        # The error and path are grype's own output: values hidden, escapes
        # and controls removed, then cut (tool_output_excerpt).
        raise ContentDatabaseAbsent(
            tool_output_excerpt(
                f"`grype db status` reports no database at {path}: {error}",
                300,
                ctx.values,
            )
        )
    if not built:
        # The status document is grype's own output: shown the same way.
        shown = tool_output_excerpt(f"{status!r}", 300, ctx.values)
        raise ValueError(f"`grype db status` reported no build time: {shown}")
    return parse_timestamp(str(built)), "`built` in `grype db status -o json`"


def _built_from_trivy(ctx: ProbeContext) -> tuple[datetime, str]:
    """``VulnerabilityDB.UpdatedAt`` from ``trivy version``, read in isolation.

    trivy loads ``trivy.yaml`` from its working directory unless ``--config`` names
    a file, and that file's ``cache.dir`` decides which database ``version``
    reports, so a probe run from ASH's own working directory could read another
    cache than the scan did. It runs from ``ctx.cwd`` instead, a directory outside
    the scanned tree (``path_trust.cwd_outside_scanned_tree``), or without one from
    the filesystem root of the temporary directory (``_probe_cwd``), with
    ``--config``: the file the scan passed trivy, or ``EMPTY_TOOL_CONFIG``. It reads
    the cache the scan was given (``--cache-dir``) when ``ctx.cache_dir`` names it.
    """
    if not ctx.executable:
        raise ValueError("trivy executable not found")
    version = _run_json(
        [
            ctx.executable,
            "version",
            "--format",
            "json",
            "--config",
            ctx.config_file or EMPTY_TOOL_CONFIG.as_posix(),
            *(["--cache-dir", ctx.cache_dir] if ctx.cache_dir else []),
        ],
        ctx.env,
        ctx=ctx,
    )
    db = version.get("VulnerabilityDB") if isinstance(version, dict) else None
    updated = db.get("UpdatedAt") if isinstance(db, dict) else None
    if not updated:
        # trivy omits VulnerabilityDB both when no database is in the cache and
        # when the database's metadata file is there but could not be read. Only
        # the first is absence (ERROR whatever the policy); the second is a
        # database of unknown age, which the policy decides. The metadata file is
        # what trivy reads for the field (pkg/db/db.go, metadata.json beside the
        # database), so its presence tells the two apart.
        metadata = (
            Path(ctx.cache_dir) / "db" / "metadata.json" if ctx.cache_dir else None
        )
        if metadata is not None and metadata.exists():
            raise ValueError(
                "`trivy version --format json` reported no VulnerabilityDB.UpdatedAt "
                f"although {metadata.as_posix()} exists; the database's metadata "
                "could not be read, so its age is unknown"
            )
        raise ContentDatabaseAbsent(
            "`trivy version --format json` reported no VulnerabilityDB.UpdatedAt; "
            "no trivy database was found in the cache directory trivy reads"
        )
    return (
        parse_timestamp(str(updated)),
        "`VulnerabilityDB.UpdatedAt` in `trivy version --format json`",
    )


def _built_from_ruleset_dir(ctx: ProbeContext) -> tuple[datetime, str]:
    if not ctx.cache_dir:
        raise ContentDatabaseAbsent("no offline rules cache directory is configured")
    cache = Path(ctx.cache_dir)
    # The rules files are counted before the manifest is read: a directory holding
    # the fetch-time record and no rules is an absent ruleset, whatever the record
    # says, and reading the manifest first reported it fresh.
    rules = [
        p for p in cache.rglob("*") if p.is_file() and p.suffix in {".yml", ".yaml"}
    ]
    if not rules:
        raise ContentDatabaseAbsent(f"no rules files found in {cache.as_posix()}")
    manifest = cache / RULESET_FETCHED_AT_FILE
    if manifest.is_file():
        text = manifest.read_text(encoding="utf-8").strip()
        if len(text) > _TIMESTAMP_TEXT_LIMIT:
            # Not a timestamp (one is under 40 characters): refused before
            # parse_timestamp quotes it whole into the record's error, its
            # message and every report.
            raise ValueError(
                f"{RULESET_FETCHED_AT_FILE} holds no timestamp: "
                f"{tool_output_excerpt(text, 60)!r}"
            )
        return (
            parse_timestamp(text),
            f"the download time recorded in {RULESET_FETCHED_AT_FILE}",
        )
    oldest = min(p.stat().st_mtime for p in rules)
    return (
        datetime.fromtimestamp(oldest, timezone.utc),
        (
            f"the oldest rules file's mtime, because {RULESET_FETCHED_AT_FILE} is absent "
            "(weaker: a plain copy resets mtime, so this can only under-state the age)"
        ),
    )


#: How each declared database's build time is read. Keyed by registry name, and held equal to
#: the registry's names by a test, so a database cannot be declared without a way to age it.
MEASURERS: Dict[str, Callable[[ProbeContext], tuple[datetime, str]]] = {
    "grype-db": _built_from_grype,
    "trivy-db": _built_from_trivy,
    "semgrep-offline-rules": _built_from_ruleset_dir,
    "opengrep-offline-rules": _built_from_ruleset_dir,
}


def measure(
    entry: ContentDatabase,
    ctx: ProbeContext,
    policy: str,
    now: Optional[datetime] = None,
    scanner: Optional[str] = None,
) -> ContentDbAgeRecord:
    """Read one database's build time. Never raises: a failure is a record of unknown age.

    ``scanner`` is the scanner that read the database. It is recorded in place of the
    entry's own ``scanner`` when it is one of the entry's ``readers``, so a database two
    scanners read is reported under the one that used it.
    """
    reader = scanner if scanner in entry.readers else entry.scanner
    now = now or datetime.now(timezone.utc)
    built: Optional[datetime] = None
    measured_by = entry.age_source
    error: Optional[str] = None
    absent = False
    try:
        measurer = MEASURERS[entry.name]
        built, measured_by = measurer(ctx)
    except Exception as exc:  # noqa: BLE001 - recorded, and counted as stale
        error = f"{type(exc).__name__}: {exc}"
        absent = isinstance(exc, ContentDatabaseAbsent)
    return ContentDbAgeRecord(
        name=entry.name,
        scanner=reader,
        built=built,
        measured_by=measured_by,
        max_age=entry.max_age,
        measured_at=now,
        policy=policy,
        bound_source=entry.bound_source,
        bound_is_tool_default=entry.bound_is_tool_default,
        refresh=entry.refresh,
        error=error,
        timestamp_label=entry.timestamp_label,
        absent=absent,
    )


def _unmeasured_record(
    entry: ContentDatabase,
    policy: str,
    now: datetime,
    scanner: Optional[str],
    failure: str,
) -> ContentDbAgeRecord:
    """The record of a database whose scanner could not describe it: unknown age, no probe.

    Built directly rather than by ``measure`` over a fabricated empty context: that
    probe ran a real measurer against nothing, so its answer (an "absent" cache, a
    missing directory) said nothing about the database the scan read and had to be
    overwritten field by field. Nothing is probed here, so the record is unmeasurable
    and not ``absent``, and the policy decides what the scan does with it.
    """
    reader = scanner if scanner in entry.readers else entry.scanner
    return ContentDbAgeRecord(
        name=entry.name,
        scanner=reader,
        built=None,
        measured_by=entry.age_source,
        max_age=entry.max_age,
        measured_at=now,
        policy=policy,
        bound_source=entry.bound_source,
        bound_is_tool_default=entry.bound_is_tool_default,
        refresh=entry.refresh,
        error=f"the scanner could not describe its database: {failure}",
        timestamp_label=entry.timestamp_label,
    )


# --------------------------------------------------------------------------- the SARIF record


def _notification(record: ContentDbAgeRecord) -> "Notification":
    from automated_security_helper.schemas.sarif_schema_model import (
        Level,
        Message,
        Message1,
        Notification,
        PropertyBag,
        ReportingDescriptorReference,
        ReportingDescriptorReference3,
    )

    return Notification(
        level=Level.error if record.policy == STALENESS_FAIL else Level.warning,
        message=Message(root=Message1(text=record.message())),
        descriptor=ReportingDescriptorReference(
            root=ReportingDescriptorReference3(id=STALE_NOTIFICATION_ID)
        ),
        timeUtc=record.measured_at,
        # model_validate rather than a keyword: PropertyBag declares only `tags` and
        # takes everything else through extra=allow, which a type checker cannot see.
        properties=PropertyBag.model_validate({"content_database": record.to_dict()}),
    )


def attach_records(sarif_report: Any, records: List[ContentDbAgeRecord]) -> None:
    """Write the records onto the report's first run's first invocation.

    Creates the run or invocation when the scanner produced none, because
    ``merge_sarif_report`` drops a report with no runs, and the record must not vanish
    with it: a stale database with zero findings is the case this exists for.
    """
    if not records:
        return
    from automated_security_helper.schemas.sarif_schema_model import (
        Invocation,
        PropertyBag,
        Run,
        Tool,
        ToolComponent,
    )

    if not sarif_report.runs:
        sarif_report.runs = [
            Run(
                tool=Tool(driver=ToolComponent(name=records[0].scanner)),
                results=[],
            )
        ]
    run = sarif_report.runs[0]
    if not run.invocations:
        run.invocations = [Invocation(executionSuccessful=True)]
    invocation = run.invocations[0]
    if invocation.properties is None:
        invocation.properties = PropertyBag()
    existing = list(
        (invocation.properties.model_extra or {}).get(INVOCATION_PROPERTY) or []
    )
    existing.extend(record.to_dict() for record in records)
    setattr(invocation.properties, INVOCATION_PROPERTY, existing)
    stale = [record for record in records if record.stale]
    if stale:
        notifications = list(invocation.toolConfigurationNotifications or [])
        failures: List[str] = []
        for record in stale:
            # One record at a time: a record whose notification cannot be built
            # must not keep every other stale database's notification out of the
            # report, which is what the exit-code gate and the reports read.
            try:
                notifications.append(_notification(record))
            except Exception as exc:  # noqa: BLE001 - the others still attach
                failures.append(f"{record.name} ({record.scanner}): {exc}")
        invocation.toolConfigurationNotifications = notifications
        if failures:
            raise RuntimeError(
                "could not record a stale-database notification for "
                + "; ".join(failures)
            )


def assess_scanner(
    scanner_plugin: Any,
    sarif_report: Any,
    policy: str,
    now: Optional[datetime] = None,
    overrides: Sequence[Any] = (),
    offline_image: bool = False,
) -> List[ContentDbAgeRecord]:
    """Measure every database this scanner used, log each stale one, and attach all of them.

    ``policy`` is the scan-wide ``content_db_staleness``; ``overrides`` are the config's
    ``content_db_staleness_overrides`` entries, and an unexpired one naming a database
    replaces ``policy`` for that database only. ``offline_image`` is
    ``resolve_offline_image_default``: whether ``OFFLINE_IMAGE_POLICIES`` replaces a
    ``fail`` policy for the databases it names, below any override entry.

    Never raises. A failure to ask the scanner which databases it used is itself recorded as
    an unmeasurable record for each database declared for it, so a defect here cannot quietly
    turn the check off. A failure to build the probe context, once the scanner has said which
    databases it read, is recorded for those databases only: a scan that read none (an online
    semgrep or opengrep, trivy without its vulnerability scanner) is not graded against the
    databases it did not read. Such a record is unmeasurable, not ``absent``: nothing was
    learned about whether the database exists, so the policy still decides what it does.
    """
    scanner_name = str(
        getattr(getattr(scanner_plugin, "config", None), "name", "") or ""
    )
    failure = ""
    try:
        entries = list(scanner_plugin.content_databases_in_use())
    except Exception as exc:  # noqa: BLE001
        entries = [e for e in CONTENT_DATABASES if scanner_name in e.readers]
        failure = f"{type(exc).__name__}: {exc}"
    if not entries:
        return []
    ctx = None
    if not failure:
        try:
            ctx = scanner_plugin.content_database_probe_context()
        except Exception as exc:  # noqa: BLE001
            failure = f"{type(exc).__name__}: {exc}"
        if ctx is None and not failure:
            # A probe context of None is a scanner that could not say where its
            # database is, not a failure that raised: the record says which.
            failure = "content_database_probe_context() returned None"

    now = now or datetime.now(timezone.utc)
    records: List[ContentDbAgeRecord] = []
    for entry in entries:
        try:
            entry_policy, policy_source = _policy_for(
                entry, policy, overrides, now, offline_image
            )
        except Exception as exc:  # noqa: BLE001 - a broken override never relaxes
            ASH_LOGGER.error(
                f"Could not apply content_db_staleness_overrides to {entry.name}: {exc}; "
                f"it is held to content_db_staleness ({policy})."
            )
            entry_policy, policy_source = policy, None
        if ctx is None:
            record = _unmeasured_record(entry, entry_policy, now, scanner_name, failure)
        else:
            record = measure(entry, ctx, entry_policy, now, scanner_name)
        record.policy_source = policy_source
        records.append(record)
        if record.stale:
            level = (
                logging.ERROR if record.policy == STALENESS_FAIL else logging.WARNING
            )
            ASH_LOGGER.log(level, record.message())
        else:
            ASH_LOGGER.info(
                f"Content database {record.name} ({record.scanner}): "
                f"{record.timestamp_label} "
                # Not stale implies a build time was read: an unread one counts as
                # stale. The guard says so to the type checker, not to a reader.
                f"{_iso(record.built) if record.built else 'unknown'}, "
                f"{format_age(record.age)} old, inside its "
                f"{go_duration(record.max_age)} bound."
            )
    try:
        attach_records(sarif_report, records)
    except Exception as exc:  # noqa: BLE001
        # attach_records attaches what it can before it raises, so a record it
        # named here is the only one missing from the report; the executor still
        # acts on every returned record.
        ASH_LOGGER.error(
            f"Could not record content database ages for {scanner_name} in its SARIF "
            f"report: {exc}"
        )
    return records


# --------------------------------------------------------------------------- reading it back


def _extra(props: Any) -> Dict[str, Any]:
    if props is None:
        return {}
    if isinstance(props, dict):
        return props
    return dict(getattr(props, "model_extra", None) or {})


def _unreadable_record(
    raw: Any, error: Exception, measured_at: Optional[datetime] = None
) -> ContentDbAgeRecord:
    """The record for a results-file entry that does not parse back.

    Stale, with the parse failure as its error and whatever name and scanner the
    entry carries: a record ASH wrote and cannot read is no evidence of a fresh
    database, and dropped it left the exit-code gate and the reports with nothing
    where the scan had recorded a failure. The bound is unknown, so the record
    carries none; ``recorded_stale`` keeps it stale whatever the bound.
    """
    data = raw if isinstance(raw, Mapping) else {}
    text = str(error) or type(error).__name__
    return ContentDbAgeRecord(
        name=str(data.get("name") or "unknown"),
        scanner=str(data.get("scanner") or "unknown"),
        built=None,
        measured_by=str(data.get("measured_by") or ""),
        max_age=timedelta(0),
        measured_at=measured_at or datetime.now(timezone.utc),
        policy=str(data.get("policy") or DEFAULT_STALENESS_POLICY),
        bound_source=str(data.get("bound_source") or ""),
        bound_is_tool_default=False,
        refresh=str(data.get("refresh") or ""),
        error=f"the recorded measurement could not be read back ({text})",
        timestamp_label=str(data.get("timestamp_label") or "built"),
        recorded_stale=True,
    )


def content_db_records(results: Any) -> List[ContentDbAgeRecord]:
    """Every content database measurement in an aggregated result, one per database and scanner.

    One scanner measured per target type writes the same database twice; the later
    measurement wins, and a stale record is kept over a fresh one for the same database and
    scanner, so a duplicate can never hide a stale reading. Two scanners that read one
    database (trivy and trivy-repo both read trivy-db) keep a record each, so a report names
    every scanner that read a stale database. Sorted by database, then scanner.
    """
    sarif = getattr(results, "sarif", None)
    by_key: Dict[Tuple[str, str], ContentDbAgeRecord] = {}
    for run in getattr(sarif, "runs", None) or []:
        for invocation in getattr(run, "invocations", None) or []:
            for raw in (
                _extra(getattr(invocation, "properties", None)).get(INVOCATION_PROPERTY)
                or []
            ):
                try:
                    record = ContentDbAgeRecord.from_dict(raw)
                except Exception as exc:  # noqa: BLE001
                    # Kept, as a stale record of unknown age: dropped, a
                    # measurement ASH wrote and cannot read vanished from
                    # every report.
                    ASH_LOGGER.warning(
                        f"Unreadable content database record {raw!r}: {exc}; "
                        "reported as a database of unknown age"
                    )
                    record = _unreadable_record(raw, exc)
                key = (record.name, record.scanner)
                current = by_key.get(key)
                if current is None or record.stale or not current.stale:
                    by_key[key] = record
    return [by_key[key] for key in sorted(by_key)]


def stale_content_databases(
    results: Any, enforced_only: bool = False
) -> List[ContentDbAgeRecord]:
    """The stale records, optionally only those that fail the scan.

    Read from the notifications rather than the property list, because the notification's
    level is what the policy decided when the scan ran; a record carried without one -- which
    nothing in ASH writes -- cannot fail a scan. One per database and scanner, as in
    ``content_db_records``, an enforced one kept over one that only warns.
    """
    sarif = getattr(results, "sarif", None)
    found: Dict[Tuple[str, str], ContentDbAgeRecord] = {}
    for run in getattr(sarif, "runs", None) or []:
        for invocation in getattr(run, "invocations", None) or []:
            for notification in (
                getattr(invocation, "toolConfigurationNotifications", None) or []
            ):
                descriptor = getattr(notification, "descriptor", None)
                ident = getattr(getattr(descriptor, "root", None), "id", None)
                if ident != STALE_NOTIFICATION_ID:
                    continue
                level = getattr(notification, "level", None)
                level = getattr(level, "value", level)
                raw = _extra(getattr(notification, "properties", None)).get(
                    "content_database"
                )
                if not raw:
                    continue
                try:
                    record = ContentDbAgeRecord.from_dict(raw)
                except Exception as exc:  # noqa: BLE001
                    # Kept, stale, under the notification's own level: the
                    # scan recorded a stale database here, and a record that
                    # does not parse back must not take it out of the gate.
                    ASH_LOGGER.warning(
                        f"Unreadable stale-database record {raw!r}: {exc}; kept "
                        "as a stale database of unknown age"
                    )
                    when = getattr(notification, "timeUtc", None)
                    record = _unreadable_record(
                        raw, exc, when if isinstance(when, datetime) else None
                    )
                # The level is authoritative for whether it fails the scan.
                record.policy = STALENESS_FAIL if level == "error" else STALENESS_WARN
                if enforced_only and not record.enforced:
                    continue
                key = (record.name, record.scanner)
                if key not in found or record.enforced:
                    found[key] = record
    return [found[key] for key in sorted(found)]


def scanners_in_error_for_a_stale_database(results: Any) -> set[str]:
    """Scanners recorded ERROR because a database the policy rejects gave a clean result.

    Under ``content_db_staleness: fail`` the executor records a clean result from a
    database past its bound as ERROR, and names the database in the per-target
    report's ``rejected_content_databases``. That ERROR is the stale database: the
    scanner ran and reached a verdict the policy does not accept. So it is reported
    once, as the stale database with its refresh advice, and the scanner counts as
    having run, as it did when such a result was recorded PASSED. A scanner in ERROR
    for any other reason is not in this set and is still reported as incomplete.

    A scanner qualifies when every per-target report of it in ERROR names a rejected
    database and nothing else, at least one does, and the results carry an enforced
    stale record for it. A report whose ERROR also carries a tool ASH could not stop
    (``could_not_stop``) or an error beyond the one per rejected database (a timeout,
    a target no rule was evaluated against) is a second coverage gap, so that scanner
    stays in the incomplete rows. A results file written before the marker existed
    has no such report, so its ERROR rows keep the stricter reading.
    """
    from automated_security_helper.core.enums import ScannerStatus

    enforced = {
        record.scanner
        for record in stale_content_databases(results, enforced_only=True)
    }
    found: set[str] = set()
    for name, reports in (getattr(results, "additional_reports", None) or {}).items():
        if name not in enforced or not isinstance(reports, Mapping):
            continue
        in_error = [
            report
            for report in reports.values()
            if isinstance(report, Mapping)
            and getattr(report.get("status"), "value", report.get("status"))
            == ScannerStatus.ERROR.value
        ]
        if in_error and all(_error_only_for_a_stale_database(r) for r in in_error):
            found.add(name)
    return found


def _error_only_for_a_stale_database(report: Mapping[str, Any]) -> bool:
    """Whether the per-target ``report``'s ERROR is its rejected databases alone.

    The executor adds one error per rejected database when it records the ERROR; a
    timeout, an unevaluated target or a stop that failed adds a line of its own, or
    sets ``could_not_stop``.
    """
    rejected = report.get("rejected_content_databases")
    if not rejected:
        return False
    if report.get("could_not_stop"):
        return False
    errors = report.get("errors")
    return not isinstance(errors, (list, tuple)) or len(errors) <= len(rejected)


def probe_env(extra: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """The environment the scanner's own subprocess ran with."""
    return {**snapshot_environ(), **(dict(extra) if extra else {})}
