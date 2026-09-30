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
  ``offline_mode_validator`` warns against the same bound;
* CI: the cache key's time bucket and the save-side freshness guard are computed by
  ``python -m automated_security_helper.utils.content_databases``, never typed into YAML;
* the drift gate ``.github/scripts/assert-content-db-caches.py``, which fails when a workflow
  caches a content database that is not declared here, or keys one without this module's
  bucket.

The inventory, and what each entry's bound is
---------------------------------------------
Read from each tool's source at the version ASH pins. The Dockerfile's ``GRYPE_VERSION`` is
v0.111.0 and its ``TRIVY_VERSION`` is v0.69.3.

grype's vulnerability database
    grype's own default is ``time.Hour * 24 * 5, // 5 days``
    (grype/db/v6/installation/curator.go:58 at v0.111.0), exposed as
    ``db.max-allowed-built-age`` / ``GRYPE_DB_MAX_ALLOWED_BUILT_AGE``, and enforced only while
    ``db.validate-age`` is true (its default, curator.go:56). With it true, a database older
    than the bound forces a download, and if the download fails the scan fails with "the
    vulnerability database was built %s ago (max allowed age is %s)" (curator.go:613). That is
    loud, which is correct. ASH declares that same 120h here and passes it explicitly.

trivy's vulnerability database
    trivy has no max-age option. Its only freshness input is the database's own
    ``NextUpdate`` metadata (pkg/db/db.go:174 at v0.69.3), and ``--skip-db-update`` bypasses
    even that (db.go:145-151). ASH does not cache it in CI, and declares no bound for it here,
    so the drift gate refuses any CI cache of it.

semgrep and opengrep offline rulesets
    Downloaded into the image at build time when ``OFFLINE=YES`` (Dockerfile, the
    ``OFFLINE_SEMGREP_RULESETS`` loop). Neither tool has any staleness check for a local rules
    file. No bound is declared, so they cannot be cached in CI either.

Where a stale database is used SILENTLY today
---------------------------------------------
In ASH's offline mode only, and recorded here rather than changed, because changing it decides
what an air-gapped user's older image does:

* grype: ``GrypeScanner`` sets ``GRYPE_DB_VALIDATE_AGE=false`` in offline mode, and grype's
  ``validateAge`` then returns nil (curator.go:603), so any age is used. ASH's own check,
  ``validate_grype_offline_mode``, warns and continues.
* trivy: ``--skip-db-update`` in offline mode uses whatever database is present, with only a
  debug-level log line.
* the rulesets: used as long as the image exists.

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


@dataclass(frozen=True)
class ContentDatabase:
    """One scanner content database, and the bound ASH holds it to."""

    name: str
    scanner: str
    cache_path: str
    max_age: timedelta | None
    # Environment variables that tell the tool the bound, with the values they must carry. Empty
    # when the tool has no such control.
    bound_env: dict[str, str] = field(default_factory=dict)
    how_enforced: str = ""

    @property
    def cacheable(self) -> bool:
        """Only a database with a declared, enforced bound may be cached."""
        return self.max_age is not None


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

CONTENT_DATABASES: tuple[ContentDatabase, ...] = (
    ContentDatabase(
        name="grype-db",
        scanner="grype",
        cache_path="~/.cache/grype/db",
        max_age=GRYPE_DB_MAX_AGE,
        bound_env={
            "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": go_duration(GRYPE_DB_MAX_AGE),
            "GRYPE_DB_VALIDATE_AGE": "true",
        },
        how_enforced=(
            "grype refuses a database built longer ago than db.max-allowed-built-age while "
            "db.validate-age is true: it downloads a newer one, and fails the scan if it "
            "cannot (grype/db/v6/installation/curator.go:219-223,603-613 at v0.111.0)"
        ),
    ),
    ContentDatabase(
        name="trivy-db",
        scanner="trivy-repo",
        cache_path="~/.cache/trivy",
        max_age=None,
        how_enforced=(
            "no max-age option exists; trivy refreshes on its own NextUpdate metadata unless "
            "--skip-db-update is passed (pkg/db/db.go:145-174 at v0.69.3)"
        ),
    ),
    ContentDatabase(
        name="semgrep-offline-rules",
        scanner="semgrep",
        cache_path="/deps/.semgrep",
        max_age=None,
        how_enforced="none: a local rules file has no staleness check in semgrep",
    ),
    ContentDatabase(
        name="opengrep-offline-rules",
        scanner="opengrep",
        cache_path="/deps/.opengrep",
        max_age=None,
        how_enforced="none: a local rules file has no staleness check in opengrep",
    ),
)


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
    if entry.max_age is None:
        raise ValueError(f"{entry.name} declares no max age, so it has no cache bucket")
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
    """Whether a database built at `built` may be saved into the cache at `now`."""
    if entry.max_age is None:
        return False
    return now - built <= entry.max_age - bucket_width(entry)


def use_allowed(entry: ContentDatabase, built: datetime, now: datetime) -> bool:
    """Whether a restored database built at `built` may be used at `now`."""
    if entry.max_age is None:
        return False
    return now - built <= entry.max_age


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
                f"{entry.name} declares no max age and must not be cached",
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
    limit = entry.max_age if args.purpose == "use" else None
    if entry.max_age is not None and args.purpose == "save":
        limit = entry.max_age - bucket_width(entry)
    age = now - built
    verdict = "allowed" if allowed else "REFUSED"
    limit_text = go_duration(limit) if limit is not None else "none declared"
    print(
        f"{entry.name}: built {built.isoformat()}, {go_duration(age)} old; "
        f"{args.purpose} {verdict} (limit {limit_text})"
    )
    return 0 if allowed else 1


if __name__ == "__main__":
    sys.exit(main())
