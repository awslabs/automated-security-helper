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
An expired entry is ignored with a warning, so the database returns to the scan-wide policy
without anyone having to remember to remove it. Either form of ``--allow-stale-content-db``
clears the list for its scan (``content_db_staleness_flag_overrides``), so the flag still
decides for every database.

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
  evidence of a fresh one, and treating it as fresh would reopen the silent case.
* The offline rulesets carry no build time of their own. The Dockerfile records the download
  time in ``RULESET_FETCHED_AT_FILE``; without it the oldest rules file's mtime is used, which
  an ordinary ``cp`` resets to the copy time and so can only under-state the age. The record
  says which source it used.
* Only scanners that return a SARIF report are measured. A scanner that failed outright is
  already reported as ERROR or MISSING, and its database contributed nothing.
"""

from __future__ import annotations

import json
import logging
import subprocess  # nosec B404 - fixed tool binaries, list arguments, no shell
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
)

from automated_security_helper.utils.content_databases import (
    CONTENT_DATABASES,
    DEFAULT_STALENESS_POLICY,
    RULESET_FETCHED_AT_FILE,
    STALENESS_FAIL,
    STALENESS_POLICIES,
    STALENESS_WARN,
    ContentDatabase,
    go_duration,
    is_stale,
    parse_timestamp,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ

if TYPE_CHECKING:
    from automated_security_helper.schemas.sarif_schema_model import Notification

STALE_NOTIFICATION_ID = "ASH-CONTENT-DB-STALE"
INVOCATION_PROPERTY = "ash_content_databases"
OPT_OUT_HINT = (
    "To scan against it anyway, pass --allow-stale-content-db or set "
    "`content_db_staleness: warn` in the ASH config."
)
_PROBE_TIMEOUT_SECONDS = 60


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
    #: ``content_db_staleness``: says which entry, and until when. Omitted from
    #: ``to_dict`` when unset, so a scan with no overrides records exactly what it did
    #: before the field existed.
    policy_source: Optional[str] = None

    @property
    def age(self) -> Optional[timedelta]:
        if self.built is None:
            return None
        return self.measured_at - self.built

    @property
    def stale(self) -> bool:
        """Past the bound, or of unknown age; see "Failure modes" in the module docstring."""
        if self.built is None:
            return True
        return is_stale(
            _registry_entry(self.name, self.max_age), self.built, self.measured_at
        )

    @property
    def enforced(self) -> bool:
        """Whether this record fails the scan: stale, under the ``fail`` policy."""
        return self.stale and self.policy == STALENESS_FAIL

    def message(self) -> str:
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
        )


def _registry_entry(name: str, max_age: timedelta) -> ContentDatabase:
    """The registry entry, or a stand-in carrying the recorded bound.

    A record read back from an older results file may name a database this ASH no longer
    declares; its own recorded bound still decides whether it was stale.
    """
    for entry in CONTENT_DATABASES:
        if entry.name == name:
            return entry
    return ContentDatabase(
        name=name,
        scanner="",
        cache_path="",
        max_age=max_age,
        bound_source="",
        bound_is_tool_default=False,
        age_source="",
        refresh="",
    )


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _policy_for(
    entry: ContentDatabase,
    policy: str,
    overrides: Sequence[Any],
    now: datetime,
) -> tuple[str, Optional[str]]:
    """The policy one database is held to, and which override chose it, if any."""
    for override in overrides:
        if getattr(override, "database", None) != entry.name:
            continue
        expires = _iso(override.expires_at)
        if override.is_expired(now):
            ASH_LOGGER.warning(
                f"The content_db_staleness_overrides entry for {entry.name} expired at "
                f"{expires} and is ignored; {entry.name} is held to "
                f"content_db_staleness ({policy}). Remove the entry from the ASH config."
            )
            return policy, None
        chosen = str(getattr(override.policy, "value", override.policy)).lower()
        if chosen not in STALENESS_POLICIES:
            return policy, None
        ASH_LOGGER.info(
            f"Content database {entry.name} is held to {chosen} rather than "
            f"content_db_staleness ({policy}) by a content_db_staleness_overrides entry "
            f"until {expires}: {override.reason}"
        )
        return chosen, (
            f"content_db_staleness_overrides entry for {entry.name}, which expires at "
            f"{expires}"
        )
    return policy, None


# --------------------------------------------------------------------------- measurement


@dataclass
class ProbeContext:
    """What a measurer needs from the scanner that used the database."""

    env: Dict[str, str]
    executable: Optional[str] = None
    cache_dir: Optional[str] = None


def _run_json(command: List[str], env: Mapping[str, str]) -> Any:
    """Run a tool's status command and parse its stdout as JSON, whatever it exits with.

    ``grype db status`` exits 1 when it considers the database invalid -- including when it
    is merely past grype's own bound -- and still prints the JSON with ``built`` in it.
    """
    proc = subprocess.run(  # nosec B603 - resolved tool binary, list arguments
        command,
        capture_output=True,
        text=True,
        env=dict(env),
        timeout=_PROBE_TIMEOUT_SECONDS,
        check=False,
    )
    text = (proc.stdout or "").strip()
    if not text:
        raise ValueError(
            f"`{' '.join(command)}` printed nothing (exit {proc.returncode}): "
            f"{(proc.stderr or '').strip()[:300]}"
        )
    return json.loads(text)


def _built_from_grype(ctx: ProbeContext) -> tuple[datetime, str]:
    if not ctx.executable:
        raise ValueError("grype executable not found")
    status = _run_json([ctx.executable, "db", "status", "-o", "json"], ctx.env)
    built = status.get("built") if isinstance(status, dict) else None
    if not built:
        raise ValueError(f"`grype db status` reported no build time: {status!r}"[:300])
    return parse_timestamp(str(built)), "`built` in `grype db status -o json`"


def _built_from_trivy(ctx: ProbeContext) -> tuple[datetime, str]:
    if not ctx.executable:
        raise ValueError("trivy executable not found")
    version = _run_json([ctx.executable, "version", "--format", "json"], ctx.env)
    db = version.get("VulnerabilityDB") if isinstance(version, dict) else None
    updated = db.get("UpdatedAt") if isinstance(db, dict) else None
    if not updated:
        raise ValueError(
            "`trivy version --format json` reported no VulnerabilityDB.UpdatedAt; "
            "no trivy database was found in the cache directory trivy reads"
        )
    return (
        parse_timestamp(str(updated)),
        "`VulnerabilityDB.UpdatedAt` in `trivy version --format json`",
    )


def _built_from_ruleset_dir(ctx: ProbeContext) -> tuple[datetime, str]:
    if not ctx.cache_dir:
        raise ValueError("no offline rules cache directory is configured")
    cache = Path(ctx.cache_dir)
    manifest = cache / RULESET_FETCHED_AT_FILE
    if manifest.is_file():
        return (
            parse_timestamp(manifest.read_text(encoding="utf-8").strip()),
            f"the download time recorded in {RULESET_FETCHED_AT_FILE}",
        )
    rules = [
        p for p in cache.rglob("*") if p.is_file() and p.suffix in {".yml", ".yaml"}
    ]
    if not rules:
        raise ValueError(f"no rules files found in {cache.as_posix()}")
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
) -> ContentDbAgeRecord:
    """Read one database's build time. Never raises: a failure is a record of unknown age."""
    now = now or datetime.now(timezone.utc)
    built: Optional[datetime] = None
    measured_by = entry.age_source
    error: Optional[str] = None
    try:
        measurer = MEASURERS[entry.name]
        built, measured_by = measurer(ctx)
    except Exception as exc:  # noqa: BLE001 - recorded, and counted as stale
        error = f"{type(exc).__name__}: {exc}"
    return ContentDbAgeRecord(
        name=entry.name,
        scanner=entry.scanner,
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
        notifications.extend(_notification(record) for record in stale)
        invocation.toolConfigurationNotifications = notifications


def assess_scanner(
    scanner_plugin: Any,
    sarif_report: Any,
    policy: str,
    now: Optional[datetime] = None,
    overrides: Sequence[Any] = (),
) -> List[ContentDbAgeRecord]:
    """Measure every database this scanner used, log each stale one, and attach all of them.

    ``policy`` is the scan-wide ``content_db_staleness``; ``overrides`` are the config's
    ``content_db_staleness_overrides`` entries, and an unexpired one naming a database
    replaces ``policy`` for that database only.

    Never raises. A failure to ask the scanner which databases it used is itself recorded as
    an unmeasurable record for each database declared for it, so a defect here cannot quietly
    turn the check off.
    """
    scanner_name = str(
        getattr(getattr(scanner_plugin, "config", None), "name", "") or ""
    )
    try:
        entries = list(scanner_plugin.content_databases_in_use())
        ctx = scanner_plugin.content_database_probe_context()
    except Exception as exc:  # noqa: BLE001
        entries = [e for e in CONTENT_DATABASES if e.scanner == scanner_name]
        ctx = None
        failure = f"{type(exc).__name__}: {exc}"
    if not entries:
        return []

    now = now or datetime.now(timezone.utc)
    records: List[ContentDbAgeRecord] = []
    for entry in entries:
        try:
            entry_policy, policy_source = _policy_for(entry, policy, overrides, now)
        except Exception as exc:  # noqa: BLE001 - a broken override never relaxes
            ASH_LOGGER.error(
                f"Could not apply content_db_staleness_overrides to {entry.name}: {exc}; "
                f"it is held to content_db_staleness ({policy})."
            )
            entry_policy, policy_source = policy, None
        if ctx is None:
            record = measure(entry, ProbeContext(env={}), entry_policy, now)
            record.error = f"the scanner could not describe its database: {failure}"
            record.built = None
        else:
            record = measure(entry, ctx, entry_policy, now)
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


def content_db_records(results: Any) -> List[ContentDbAgeRecord]:
    """Every content database measurement in an aggregated result, deduplicated.

    One scanner measured per target type writes the same database twice; the later
    measurement of a database wins, and a stale record is kept over a fresh one for the same
    database, so a duplicate can never hide a stale reading.
    """
    sarif = getattr(results, "sarif", None)
    by_name: Dict[str, ContentDbAgeRecord] = {}
    for run in getattr(sarif, "runs", None) or []:
        for invocation in getattr(run, "invocations", None) or []:
            for raw in (
                _extra(getattr(invocation, "properties", None)).get(INVOCATION_PROPERTY)
                or []
            ):
                try:
                    record = ContentDbAgeRecord.from_dict(raw)
                except Exception as exc:  # noqa: BLE001
                    ASH_LOGGER.debug(
                        f"Unreadable content database record {raw!r}: {exc}"
                    )
                    continue
                current = by_name.get(record.name)
                if current is None or record.stale or not current.stale:
                    by_name[record.name] = record
    return [by_name[name] for name in sorted(by_name)]


def stale_content_databases(
    results: Any, enforced_only: bool = False
) -> List[ContentDbAgeRecord]:
    """The stale records, optionally only those that fail the scan.

    Read from the notifications rather than the property list, because the notification's
    level is what the policy decided when the scan ran; a record carried without one -- which
    nothing in ASH writes -- cannot fail a scan.
    """
    sarif = getattr(results, "sarif", None)
    found: Dict[str, ContentDbAgeRecord] = {}
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
                    ASH_LOGGER.debug(f"Unreadable stale-database record {raw!r}: {exc}")
                    continue
                # The level is authoritative for whether it fails the scan.
                record.policy = STALENESS_FAIL if level == "error" else STALENESS_WARN
                if enforced_only and not record.enforced:
                    continue
                if record.name not in found or record.enforced:
                    found[record.name] = record
    return [found[name] for name in sorted(found)]


def probe_env(extra: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """The environment the scanner's own subprocess ran with."""
    return {**snapshot_environ(), **(dict(extra) if extra else {})}
