# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from stat import S_ISREG
from typing import TYPE_CHECKING, Callable, Dict

from automated_security_helper.utils.content_databases import (
    StalenessPolicy,
    get,
    go_duration,
    is_future_dated,
    is_stale,
    parse_timestamp,
)
from automated_security_helper.utils.content_db_refresh import default_cache_dir
from automated_security_helper.utils.content_db_staleness import cache_check_policy
from automated_security_helper.utils.process_env import snapshot_environ

if TYPE_CHECKING:
    from automated_security_helper.config.ash_config import AshConfig


class CacheState(str, Enum):
    FRESH = "fresh"
    STALE = "stale"
    MISSING = "missing"
    INVALID = "invalid"


@dataclass(frozen=True)
class OfflineCacheResult:
    tool: OfflineCacheTool
    database: Path
    state: CacheState
    policy: StalenessPolicy
    policy_source: str | None
    max_age: str
    built: datetime | None = None
    detail: str | None = None

    @property
    def blocks(self) -> bool:
        return self.state in {CacheState.MISSING, CacheState.INVALID} or (
            self.state == CacheState.STALE and self.policy == StalenessPolicy.FAIL
        )


class InvalidCache(ValueError):
    pass


_GRYPE_SCHEMA = 6
_TRIVY_SCHEMA = 2
_MAX_METADATA_BYTES = 64 * 1024


def _require_regular_data(path: Path) -> None:
    attributes = path.stat()
    if not S_ISREG(attributes.st_mode) or attributes.st_size == 0:
        raise InvalidCache(f"{path.name} is not a nonempty regular file")


def _timestamp(value: object) -> datetime:
    if (
        isinstance(value, str)
        and 0 < len(value) <= 64
        and not value.strip().startswith("0001-01-01")
    ):
        try:
            return parse_timestamp(value)
        except ValueError:
            pass
    raise InvalidCache("database metadata has no valid build timestamp")


def _grype_built(path: Path) -> datetime:
    try:
        import sqlite3
    except ImportError:
        raise InvalidCache("this Python build does not support SQLite") from None

    for suffix in ("-wal", "-journal"):
        try:
            attributes = path.with_name(path.name + suffix).stat()
        except FileNotFoundError:
            continue
        if attributes.st_size:
            raise InvalidCache(
                "Grype database has a transaction sidecar; check it when idle"
            )
    try:
        with closing(
            sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
        ) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            rows = db.execute(
                "SELECT build_timestamp, model FROM db_metadata LIMIT 2"
            ).fetchall()
    except sqlite3.Error:
        raise InvalidCache("could not read Grype's SQLite metadata") from None
    if len(rows) != 1 or rows[0][1] != _GRYPE_SCHEMA:
        raise InvalidCache("Grype metadata does not identify one schema 6 database")
    return _timestamp(rows[0][0])


def _trivy_built(path: Path) -> datetime:
    with path.open("rb") as contents:
        if not contents.read(1):
            raise InvalidCache("Trivy database is empty")
    metadata = path.with_name("metadata.json")
    _require_regular_data(metadata)
    with metadata.open("rb") as contents:
        raw = contents.read(_MAX_METADATA_BYTES + 1)
    if len(raw) > _MAX_METADATA_BYTES:
        raise InvalidCache("Trivy metadata is too large")
    try:
        record = json.loads(raw)
    except (ValueError, RecursionError):
        raise InvalidCache("Trivy metadata is not a valid JSON document") from None
    if (
        not isinstance(record, dict)
        or type(record.get("Version")) is not int
        or record["Version"] != _TRIVY_SCHEMA
    ):
        raise InvalidCache("Trivy metadata does not identify schema 2")
    return _timestamp(record.get("UpdatedAt"))


@dataclass(frozen=True)
class OfflineChecker:
    """How one content database is checked without running its tool."""

    tool: str
    relpath: tuple[str, ...]
    read_built: Callable[[Path], datetime]


# Keyed by CONTENT_DATABASES name, like content_db_staleness.MEASURERS. A test
# holds every key to a registry name, so a database cannot be checkable without
# being declared.
OFFLINE_CHECKERS: Dict[str, OfflineChecker] = {
    "grype-db": OfflineChecker(
        "grype", (str(_GRYPE_SCHEMA), "vulnerability.db"), _grype_built
    ),
    "trivy-db": OfflineChecker("trivy", ("db", "trivy.db"), _trivy_built),
}


class OfflineCacheTool(str, Enum):
    """The CLI's --tool choices.

    Written out literally so mypy can read the members. A test holds these to
    the tools declared in OFFLINE_CHECKERS, in both directions.
    """

    GRYPE = "grype"
    TRIVY = "trivy"


def check_offline_cache(
    tool: OfflineCacheTool, config: AshConfig, now: datetime | None = None
) -> OfflineCacheResult:
    now = now or datetime.now(timezone.utc)
    environ = snapshot_environ()
    name, checker = next(
        (name, checker)
        for name, checker in OFFLINE_CHECKERS.items()
        if checker.tool == tool.value
    )
    entry = get(name)
    policy, source = cache_check_policy(entry, config, now, environ)
    db_path = default_cache_dir(checker.tool, environ).joinpath(*checker.relpath)
    read_built = checker.read_built

    built = None
    detail = None
    try:
        _require_regular_data(db_path)
        built = read_built(db_path)
        if is_future_dated(built, now):
            detail = "the build timestamp is ahead of this host's clock"
        state = CacheState.STALE if is_stale(entry, built, now) else CacheState.FRESH
    except FileNotFoundError as exc:
        state = CacheState.MISSING
        missing = Path(exc.filename).name if exc.filename else db_path.name
        detail = f"{missing} is missing"
    except InvalidCache as exc:
        state, detail = CacheState.INVALID, str(exc)
    except (OSError, ValueError):
        state, detail = CacheState.INVALID, "cache metadata could not be read"

    return OfflineCacheResult(
        tool, db_path, state, policy, source, go_duration(entry.max_age), built, detail
    )
