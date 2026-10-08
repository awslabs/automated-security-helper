# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner content databases ASH knows about, and the age bound each one is held to.

Why this module exists
----------------------
A vulnerability database is only as good as it is recent, and a cache is the easiest way to
make one old without anyone noticing. Saving CI caches on main only bounds how much the cache
holds. It does not bound how old an entry gets while it keeps being restored. So a cached
database has to expire on the same clock the scanner itself enforces. The two can only
provably agree if both read one declared number, which is this table.

It follows the same rule as ``scanner_names.py`` and ``tool_downloads.py``: a value restated by
hand in two places drifts. Everything that needs a database's age bound reads it from here:

* the runtime: ``GrypeScanner`` passes ``GRYPE_DB_MAX_ALLOWED_BUILT_AGE`` from this table rather
  than leaning on grype's built-in default, so the bound is declared rather than inherited;
  ``offline_mode_validator`` warns against the same bounds;
* the scan-time staleness check, ``utils/content_db_staleness.py``: after every scanner that
  reads one of these databases, ASH reads the database's own build timestamp and holds it to
  ``max_age`` here, in online and offline mode alike. Past the bound the scan fails by default
  (``content_db_staleness: fail``); ``content_db_staleness: warn`` or
  ``--allow-stale-content-db`` downgrades that to a warning carried in the reports;
* CI: the cache key's time bucket and the save-side freshness guard are computed by
  ``python -m automated_security_helper.utils.content_databases``, never typed into YAML;
* the drift gate ``.github/scripts/assert-content-db-caches.py``, which fails when a workflow
  caches a content database that is not declared here, or keys one without this module's
  bucket; and ``tests/unit/utils/test_content_db_staleness.py``, which fails when a scanner
  that keeps an offline cache is neither declared here nor listed in
  ``SCANNERS_WITHOUT_CONTENT_DATABASE`` with the reason it reads none.

The inventory, and what each entry's bound is
---------------------------------------------
Read from each tool's source at the version ASH pins. The Dockerfile's ``GRYPE_VERSION`` is
v0.120.1 and its ``TRIVY_VERSION`` is v0.75.0. Each entry also says, in ``bound_source``,
where its number comes from, and ``bound_is_tool_default`` separates a number the tool itself
enforces from one ASH chose.

grype's vulnerability database
    grype's own default is ``time.Hour * 24 * 5, // 5 days``
    (grype/db/v6/installation/curator.go:58 at v0.120.1), exposed as
    ``db.max-allowed-built-age`` / ``GRYPE_DB_MAX_ALLOWED_BUILT_AGE``, and enforced only while
    ``db.validate-age`` is true (its default, curator.go:56). With it true, a database older
    than the bound forces a download, and if the download fails the scan fails with "the
    vulnerability database was built %s ago (max allowed age is %s)" (curator.go:615). That is
    loud, which is correct. ASH declares that same 120h here and passes it explicitly. Age is
    read from ``built`` in ``grype db status -o json``, the timestamp grype itself checks.

trivy's vulnerability database
    trivy has no max-age option. Its freshness rule is the database's own ``NextUpdate``
    metadata: a database is current while ``now`` is before it, and is replaced once it passes
    (``isNewDB``, pkg/db/db.go:172-183 at v0.75.0). The published database sets
    ``NextUpdate`` to its build time plus the builder's ``--update-interval``
    (trivy-db pkg/vulndb/db.go:90), which the publishing build passes as ``24h``
    (trivy-db Makefile:94, and the flag's default in pkg/app.go:50, at trivy-db commit
    650c4091). So trivy's own bound for its official database is 24 hours from ``UpdatedAt``,
    and that is the number declared. Age is read from ``VulnerabilityDB.UpdatedAt`` in
    ``trivy version --format json``. Online, trivy replaces a database past ``NextUpdate``
    before scanning and fails if it cannot; offline, ``--skip-db-update`` bypasses the rule
    entirely (db.go:145-151), which is the case ASH's check exists for.

semgrep and opengrep offline rulesets
    Downloaded into the image at build time when ``OFFLINE=YES`` (Dockerfile, the
    ``OFFLINE_SEMGREP_RULESETS`` loop), which also writes the download time to
    ``RULESET_FETCHED_AT_FILE`` in each cache directory. Neither tool has any staleness
    notion for a local rules file, so the bound here is ASH's own choice and not a tool
    default; the reasoning is on the entry. Online, semgrep and opengrep fetch the rules at
    scan time and no local copy is involved, so the check applies to offline runs only.

Where a stale database used to be used SILENTLY
-----------------------------------------------
Until the scan-time check existed, in ASH's offline mode:

* grype: ``GrypeScanner`` sets ``GRYPE_DB_VALIDATE_AGE=false`` in offline mode, and grype's
  ``validateAge`` then returns nil (curator.go:605), so any age was used. Measured with grype
  v0.111.0: a database built 10 days earlier scanned with exit 0 and no warning, and ASH's
  ``validate_grype_offline_mode`` reported it "0 days old" because it read file mtime.
* trivy: ``--skip-db-update`` uses whatever database is present, with only a debug-level line.
* the rulesets: used as long as the image existed.

grype and trivy are still run that way offline; ASH measures the database afterwards rather
than handing the tool a bound it would enforce by trying to download, which an air-gapped host
cannot do.

Constraints
-----------
Standard library only. CI runs this module with the runner's python before ASH's dependencies
are installed.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# The key prefix's version. Bump it when the bucket arithmetic changes, so entries keyed under
# the old arithmetic are never restored by the new one.
KEY_VERSION = "v1"

# How many buckets fit in one max age. See ``bucket_width`` for why the guarantee needs more
# than one, and why five: it keeps grype's 120h bound on a 24h bucket, the cadence the grype
# cache already rotated on before this module existed.
BUCKETS_PER_MAX_AGE = 5


#: How a stale content database is handled at scan time, set per scan by the
#: ``content_db_staleness`` config field or ``--allow-stale-content-db``. ``fail`` is the
#: default: a scan whose database is past its bound exits 1. ``warn`` lets it proceed and
#: carries a warning into the log and every report.
STALENESS_FAIL = "fail"
STALENESS_WARN = "warn"
STALENESS_POLICIES = (STALENESS_FAIL, STALENESS_WARN)
DEFAULT_STALENESS_POLICY = STALENESS_FAIL
STALENESS_CONFIG_FIELD = "content_db_staleness"
#: Per-database exceptions to ``content_db_staleness``, each with a required expiration date.
STALENESS_OVERRIDES_CONFIG_FIELD = "content_db_staleness_overrides"


def content_db_staleness_override(allow_stale: bool) -> str:
    """The ``--config-overrides`` entry ``--allow-stale-content-db`` (or its ``--no-`` form) means."""
    return (
        f"{STALENESS_CONFIG_FIELD}={STALENESS_WARN if allow_stale else STALENESS_FAIL}"
    )


def content_db_staleness_flag_overrides(allow_stale: bool) -> list[str]:
    """Every ``--config-overrides`` entry either form of the flag means.

    The policy, and an empty ``content_db_staleness_overrides``: the flag decides for one
    scan and every database, so a per-database entry in the config file cannot outrank it.
    Without the second entry, ``--no-allow-stale-content-db`` would not restore ``fail``
    for a database the config file relaxes.
    """
    return [
        content_db_staleness_override(allow_stale),
        f"{STALENESS_OVERRIDES_CONFIG_FIELD}=[]",
    ]


#: Written next to an offline ruleset when it is downloaded, holding the download time as an
#: RFC 3339 UTC timestamp. A rules file carries no build time of its own, and its mtime is
#: reset by an ordinary ``cp``, so the download records the time explicitly. No extension, so
#: neither semgrep nor opengrep tries to load it as a rule file from the ``--config`` directory.
RULESET_FETCHED_AT_FILE = ".ash-rules-fetched-at"


@dataclass(frozen=True)
class ContentDatabase:
    """One scanner content database, and the bound ASH holds it to."""

    name: str
    scanner: str
    cache_path: str
    max_age: timedelta
    # Where the number comes from: a citation to the tool's source at the pinned version, or,
    # when ``bound_is_tool_default`` is False, ASH's reasoning for choosing it.
    bound_source: str
    bound_is_tool_default: bool
    # What timestamp the age is measured from, and how it is read.
    age_source: str
    # What an operator does to get a fresh copy. Shown in the staleness message.
    refresh: str
    # Environment variables that tell the tool the bound, with the values they must carry. Empty
    # when the tool has no such control.
    bound_env: dict[str, str] = field(default_factory=dict)
    how_enforced: str = ""
    # The verb for the timestamp ``age_source`` reads, as the staleness message prints it:
    # a vulnerability database is built, an offline ruleset is downloaded.
    timestamp_label: str = "built"
    # Whether CI may cache this database. Only grype's is, because only grype's has the CI
    # restore and save guards (`check-age`) the bucket argument on ``bucket_width`` relies on.
    # A declared max age alone is not enough: it bounds what a SCAN accepts, not what a cache
    # hands out, and the drift gate refuses a CI cache of anything not marked here.
    cacheable_in_ci: bool = False

    @property
    def cacheable(self) -> bool:
        """Only a database with an enforced bound AND the CI age guards may be cached in CI."""
        return self.cacheable_in_ci


def go_duration(value: timedelta) -> str:
    """A Go ``time.Duration`` string, which is what grype parses the bound from."""
    seconds = int(value.total_seconds())
    sign = "-" if seconds < 0 else ""
    hours, rest = divmod(abs(seconds), 3600)
    minutes, secs = divmod(rest, 60)
    if minutes == 0 and secs == 0:
        return f"{sign}{hours}h"
    return f"{sign}{hours}h{minutes}m{secs}s"


GRYPE_DB_MAX_AGE = timedelta(hours=120)
TRIVY_DB_MAX_AGE = timedelta(hours=24)
# ASH's own choice for both offline rulesets; see OFFLINE_RULESET_BOUND_REASON.
OFFLINE_RULESET_MAX_AGE = timedelta(days=30)

OFFLINE_RULESET_BOUND_REASON = (
    "ASH's own choice, not a tool default: neither semgrep nor opengrep has any notion of a "
    "local rules file going stale, so there is no tool number to adopt. 30 days because a "
    "ruleset encodes code patterns rather than advisories, and ages more slowly than a "
    "vulnerability feed: holding it to grype's 5 days would fail every air-gapped image "
    "within a week over content that changes over weeks. But the registry packs keep "
    "gaining new and corrected rules, and with no bound at all an image can scan with "
    "rules years old while every report reads as current. A month bounds an offline image "
    "to a monthly rebuild for its rules; its grype database, if it has one, needs a rebuild "
    "far sooner anyway."
)

CONTENT_DATABASES: tuple[ContentDatabase, ...] = (
    ContentDatabase(
        name="grype-db",
        scanner="grype",
        cache_path="~/.cache/grype/db",
        max_age=GRYPE_DB_MAX_AGE,
        bound_source=(
            "grype's own default, `time.Hour * 24 * 5` "
            "(grype/db/v6/installation/curator.go:58 at v0.120.1)"
        ),
        bound_is_tool_default=True,
        age_source="`built` in `grype db status -o json`, the database's own build time",
        refresh=(
            "run `grype db update` with network access, or rebuild the offline image "
            "(`ash build-image --offline`) so it downloads a current database"
        ),
        bound_env={
            "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": go_duration(GRYPE_DB_MAX_AGE),
            "GRYPE_DB_VALIDATE_AGE": "true",
        },
        how_enforced=(
            "grype refuses a database built longer ago than db.max-allowed-built-age while "
            "db.validate-age is true: it downloads a newer one, and fails the scan if it "
            "cannot (grype/db/v6/installation/curator.go:221-225,605-615 at v0.120.1). "
            "Offline, validate-age is off, and ASH's scan-time check holds the same bound"
        ),
        cacheable_in_ci=True,
    ),
    ContentDatabase(
        name="trivy-db",
        scanner="trivy-repo",
        cache_path="~/.cache/trivy",
        max_age=TRIVY_DB_MAX_AGE,
        bound_source=(
            "trivy's own rule: a database is current until its NextUpdate "
            "(pkg/db/db.go:172-183 at v0.75.0), and the published database's NextUpdate is "
            "its UpdatedAt plus `--update-interval 24h` (trivy-db Makefile:94 and "
            "pkg/vulndb/db.go:90 at 650c4091)"
        ),
        bound_is_tool_default=True,
        age_source=(
            "`VulnerabilityDB.UpdatedAt` in `trivy version --format json`, the database's "
            "own build time"
        ),
        refresh=(
            "run `trivy image --download-db-only` with network access, or copy a current "
            "trivy database into the cache directory trivy reads"
        ),
        how_enforced=(
            "no max-age option exists; trivy refreshes on its own NextUpdate metadata unless "
            "--skip-db-update is passed (pkg/db/db.go:145-174 at v0.75.0). ASH's scan-time "
            "check holds it to the bound in both modes"
        ),
    ),
    ContentDatabase(
        name="semgrep-offline-rules",
        scanner="semgrep",
        cache_path="/deps/.semgrep",
        max_age=OFFLINE_RULESET_MAX_AGE,
        bound_source=OFFLINE_RULESET_BOUND_REASON,
        bound_is_tool_default=False,
        timestamp_label="downloaded",
        age_source=(
            f"the download time in `{RULESET_FETCHED_AT_FILE}` in the cache directory, "
            "else the oldest rules file's mtime"
        ),
        refresh=(
            "rebuild the offline image (`ash build-image --offline`), which downloads the "
            "rulesets again, or download them into $SEMGREP_RULES_CACHE_DIR and record the "
            f"time in {RULESET_FETCHED_AT_FILE}"
        ),
        how_enforced=(
            "none in semgrep: a local rules file has no staleness check. ASH's scan-time "
            "check holds it to the bound in offline mode, the only mode that uses it"
        ),
    ),
    ContentDatabase(
        name="opengrep-offline-rules",
        scanner="opengrep",
        cache_path="/deps/.opengrep",
        max_age=OFFLINE_RULESET_MAX_AGE,
        bound_source=OFFLINE_RULESET_BOUND_REASON,
        bound_is_tool_default=False,
        timestamp_label="downloaded",
        age_source=(
            f"the download time in `{RULESET_FETCHED_AT_FILE}` in the cache directory, "
            "else the oldest rules file's mtime"
        ),
        refresh=(
            "rebuild the offline image (`ash build-image --offline`), which downloads the "
            "rulesets again, or download them into $OPENGREP_RULES_CACHE_DIR and record the "
            f"time in {RULESET_FETCHED_AT_FILE}"
        ),
        how_enforced=(
            "none in opengrep: a local rules file has no staleness check. ASH's scan-time "
            "check holds it to the bound in offline mode, the only mode that uses it"
        ),
    ),
)

#: Scanners that keep an offline cache (``OfflineStrategy.CACHE_FLAGS``) yet read no content
#: database whose age matters, each with the reason. A scanner of that strategy that is in
#: neither this table nor ``CONTENT_DATABASES`` fails
#: ``tests/unit/utils/test_content_db_staleness.py``, so a new database-reading scanner cannot
#: arrive without a bound.
SCANNERS_WITHOUT_CONTENT_DATABASE: dict[str, str] = {
    "checkov": (
        "its policies ship inside the checkov package ASH pins, so they age with the "
        "package version rather than with a separately downloaded database; offline mode "
        "only stops it fetching platform policies"
    ),
    "npm-audit": (
        "advisories come from the npm registry's audit endpoint at scan time; npm keeps no "
        "local advisory database for offline mode to read"
    ),
    "syft": (
        "it catalogs packages and matches nothing against advisories; offline mode only "
        "disables its update check"
    ),
}


def get(name: str) -> ContentDatabase:
    for entry in CONTENT_DATABASES:
        if entry.name == name:
            return entry
    raise KeyError(f"no content database named {name!r} is declared")


def bucket_width(entry: ContentDatabase) -> timedelta:
    """How long one cache key stays current.

    THE ARGUMENT. Let W be the bucket width and M the max age. An entry is saved at time s into
    bucket b = floor(s / W), and a key only matches runs in the same bucket, so it is restored
    at some time r < (b + 1) * W <= s + W. The database in it was already a = s - built old
    when saved. So at use its age is a + (r - s) < a + W.

    A bucket equal to M does not hold the bound: an entry saved just after a bucket starts is
    restored until the bucket ends, so with a database already near M at save time it is handed
    out at nearly 2M. Two things close that:

    1. W = M / BUCKETS_PER_MAX_AGE, so the key alone caps (r - s) at M/5.
    2. The save is refused unless the database's age at save is at most M - W
       (``save_allowed``), so a + W <= M.

    Together, age at use < (M - W) + W = M. There is no prefix fallback (`restore-keys`) to an
    older bucket, because that would reintroduce the unbounded case; the drift gate enforces
    its absence.
    """
    if not entry.cacheable:
        raise ValueError(
            f"{entry.name} is not cacheable in CI, so it has no cache bucket"
        )
    return entry.max_age / BUCKETS_PER_MAX_AGE


def bucket(entry: ContentDatabase, now: datetime) -> int:
    width = int(bucket_width(entry).total_seconds())
    return int(now.timestamp()) // width


def cache_key_suffix(entry: ContentDatabase, now: datetime) -> str:
    """The time-bucket part of a CI cache key: `<name>-<version>-w<width>-b<bucket>`.

    The width is in the key so a changed max age can never match an entry cut on the old one.
    """
    width = int(bucket_width(entry).total_seconds())
    return f"{entry.name}-{KEY_VERSION}-w{width}-b{bucket(entry, now)}"


def save_allowed(entry: ContentDatabase, built: datetime, now: datetime) -> bool:
    """Whether a database built at `built` may be saved into the CI cache at `now`."""
    if not entry.cacheable:
        return False
    return now - built <= entry.max_age - bucket_width(entry)


def use_allowed(entry: ContentDatabase, built: datetime, now: datetime) -> bool:
    """Whether a database built at `built`, restored from the CI cache, may be used at `now`."""
    if not entry.cacheable:
        return False
    return now - built <= entry.max_age


def is_stale(entry: ContentDatabase, built: datetime, now: datetime) -> bool:
    """Whether a database built at `built` is past its bound at `now`, for a scan.

    Separate from ``use_allowed`` on purpose. That answers a CI-cache question and refuses
    anything not cacheable there; this answers "may a scan trust it", which every declared
    database has an answer to.
    """
    return now - built > entry.max_age


def parse_timestamp(value: str) -> datetime:
    """An RFC 3339 timestamp as grype prints it, which may carry nanoseconds.

    Go's time.Time marshals up to nine fractional digits; Python's fromisoformat takes six,
    so the rest is truncated rather than rejected.
    """
    text = value.strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp {value!r} carries no timezone")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m automated_security_helper.utils.content_databases",
        description="Cache keys and freshness checks for scanner content databases.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p_key = sub.add_parser(
        "cache-key", help="print the time-bucket part of the cache key"
    )
    p_key.add_argument("name")
    p_check = sub.add_parser(
        "check-age",
        help="exit 0 if a database built at --built may be used or saved now, 1 if not",
    )
    p_check.add_argument("name")
    p_check.add_argument("--built", required=True, help="RFC 3339 build timestamp")
    p_check.add_argument(
        "--for", dest="purpose", choices=("use", "save"), required=True
    )
    p_env = sub.add_parser(
        "bound-env", help="print NAME=value lines telling the tool its bound"
    )
    p_env.add_argument("name")
    args = parser.parse_args(argv)

    try:
        entry = get(args.name)
    except KeyError as exc:
        print(exc.args[0], file=sys.stderr)
        return 2
    now = datetime.now(timezone.utc)

    if args.command == "cache-key":
        if not entry.cacheable:
            print(
                f"{entry.name} is not declared cacheable in CI and must not be cached",
                file=sys.stderr,
            )
            return 2
        print(cache_key_suffix(entry, now))
        return 0
    if args.command == "bound-env":
        for name, value in entry.bound_env.items():
            print(f"{name}={value}")
        return 0

    built = parse_timestamp(args.built)
    allowed = (save_allowed if args.purpose == "save" else use_allowed)(
        entry, built, now
    )
    limit = None
    if entry.cacheable:
        limit = entry.max_age
        if args.purpose == "save":
            limit = entry.max_age - bucket_width(entry)
    age = now - built
    verdict = "allowed" if allowed else "REFUSED"
    limit_text = go_duration(limit) if limit is not None else "not cacheable in CI"
    print(
        f"{entry.name}: built {built.isoformat()}, {go_duration(age)} old; "
        f"{args.purpose} {verdict} (limit {limit_text})"
    )
    return 0 if allowed else 1


if __name__ == "__main__":
    sys.exit(main())
