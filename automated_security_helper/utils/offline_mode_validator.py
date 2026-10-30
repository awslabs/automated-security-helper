# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline mode validation utilities for ASH scanners."""

import os
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime, timedelta, timezone

from automated_security_helper.utils.content_databases import (
    get as get_content_database,
    go_duration,
)
from automated_security_helper.utils.log import ASH_LOGGER

#: The one file that is grype's vulnerability database inside its cache
#: (``<cache>/<schema>/vulnerability.db``). The cache holds other files beside it
#: (listing metadata, a schema directory of an older version), and counting any
#: ``.db`` or any name holding "vulnerability" read those as the database: a
#: cache with no database passed as valid, and a newer unrelated file hid a
#: stale database from the age check.
GRYPE_DATABASE_FILE = "vulnerability.db"

#: The one file that is trivy's vulnerability database (``<cache>/db/trivy.db``).
#: trivy's cache also holds its scan cache (``fanal/fanal.db``) and the Java
#: index (``java-db/trivy-java.db``), neither of which is the vulnerability
#: database, and a name test on ".db" or "trivy" counted both.
TRIVY_DATABASE_FILE = "trivy.db"


def _guarded(scanner: str, check) -> Tuple[bool, List[str]]:
    """``check()``, with a filesystem error answered as a failed validation.

    The validators read the cache directory and stat each database file after
    the glob that found it; a file removed in between, or one this process may
    not read, raised out of the scanner's constructor, and the scanner was
    dropped from the run without a word. These checks are advisory, so an
    unreadable cache is reported the way an empty one is. A modification time
    the platform cannot turn into a date (``datetime.fromtimestamp`` raises
    OverflowError or ValueError for one outside its range) is answered the same
    way: it says nothing about the database, and it must not drop the scanner.
    """
    try:
        return check()
    except (OSError, OverflowError, ValueError) as exc:
        message = (
            f"{scanner} offline mode: the cache could not be validated: "
            f"{type(exc).__name__}: {exc}"
        )
        ASH_LOGGER.warning(message)
        return False, [message]


def _cache_directory(tool: str, variable: str) -> Tuple[str, Optional[str]]:
    """``(directory, note)``: the cache directory the scan reads for ``tool``.

    ``variable`` names the tool's own cache variable. When it is unset the scan
    does not fail: grype and trivy read their default cache directory, which
    ``content_db_refresh.default_cache_dir`` resolves as the tools do, so a
    correctly provisioned default-layout cache is inspected rather than
    reported missing for want of a variable the scanners never required. The
    note says which directory was taken and why.
    """
    from_env = os.environ.get(variable)
    if from_env:
        return from_env, None
    from automated_security_helper.utils.content_db_refresh import default_cache_dir

    directory = str(default_cache_dir(tool))
    return directory, f"{variable} not set; checking the default cache {directory}"


def _database_age(newest: Path) -> timedelta:
    """How old ``newest`` is by its modification time, never negative.

    A file dated in the future (a clock that moved, a copy that kept a later
    host's time) gave a negative age, which ``timedelta.days`` prints as -1. The
    floor is zero: the file is at least as new as now.

    Both instants are taken in UTC. Two naive local times straddling the zone's
    clock change differ by an hour from the elapsed time, so a database written
    thirty days before a read made after that change read "29 days old".
    """
    written = datetime.fromtimestamp(newest.stat().st_mtime, timezone.utc)
    age = datetime.now(timezone.utc) - written
    return max(age, timedelta(0))


def validate_grype_offline_mode() -> Tuple[bool, List[str]]:
    """
    Validate that Grype offline mode requirements are met.

    Returns:
        Tuple of (is_valid, list_of_messages)
    """
    return _guarded("Grype", _validate_grype_offline_mode)


def _validate_grype_offline_mode() -> Tuple[bool, List[str]]:
    messages = []
    is_valid = True

    cache_dir, note = _cache_directory("grype", "GRYPE_DB_CACHE_DIR")
    if note is not None:
        ASH_LOGGER.info(f"Grype offline mode: {note}")
        messages.append(note)

    cache_path = Path(cache_dir)
    if not cache_path.exists():
        ASH_LOGGER.warning(
            f"Grype offline mode: Cache directory does not exist: {cache_dir}"
        )
        messages.append(f"Cache directory does not exist: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # The vulnerability database itself, wherever it sits under the cache (grype
    # keeps it under a schema-version directory). Not any .db or any name holding
    # "vulnerability": see GRYPE_DATABASE_FILE.
    db_files = [
        item
        for item in cache_path.glob("**/*")
        if item.name == GRYPE_DATABASE_FILE and item.is_file()
    ]

    if not db_files:
        ASH_LOGGER.warning(
            f"Grype offline mode: No database files found in cache directory: {cache_dir}"
        )
        messages.append(f"No database files found in cache directory: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # Warn against the bound grype itself enforces online, declared once in
    # utils/content_databases.py. This used to be a separate 7-day literal, looser
    # than grype's own bound, so an offline database could be two days past the
    # point an online scan would refuse it before anything said so. Still a warning, and
    # still read from file mtime, which a copy resets (a 10-day-old database copied into
    # place reads "0 days old" here). The authoritative check is the one after the scan in
    # utils/content_db_staleness.py, which reads grype's own `built` timestamp and fails
    # the scan by default.
    grype_max_age = get_content_database("grype-db").max_age
    newest_db = max(db_files, key=lambda f: f.stat().st_mtime)
    db_age = _database_age(newest_db)

    if grype_max_age is not None and db_age > grype_max_age:
        ASH_LOGGER.warning(
            f"Grype offline mode: Database is {db_age.days} days old, past the "
            f"{go_duration(grype_max_age)} bound grype enforces online; consider updating"
        )
        messages.append(
            f"Database is {db_age.days} days old, past the "
            f"{go_duration(grype_max_age)} bound, consider updating"
        )
    else:
        ASH_LOGGER.info(
            f"Grype offline mode: Found {len(db_files)} database files, newest is {db_age.days} days old"
        )
        messages.append(
            f"Found {len(db_files)} database files, newest is {db_age.days} days old"
        )

    return is_valid, messages


def validate_trivy_offline_mode() -> Tuple[bool, List[str]]:
    """
    Validate that Trivy offline mode requirements are met.

    Returns:
        Tuple of (is_valid, list_of_messages)
    """
    return _guarded("Trivy", _validate_trivy_offline_mode)


def _validate_trivy_offline_mode() -> Tuple[bool, List[str]]:
    messages = []
    is_valid = True

    cache_dir, note = _cache_directory("trivy", "TRIVY_CACHE_DIR")
    if note is not None:
        ASH_LOGGER.info(f"Trivy offline mode: {note}")
        messages.append(note)

    cache_path = Path(cache_dir)
    if not cache_path.exists():
        ASH_LOGGER.warning(
            f"Trivy offline mode: Cache directory does not exist: {cache_dir}"
        )
        messages.append(f"Cache directory does not exist: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # The vulnerability database itself (db/trivy.db), not the scan cache or the
    # Java index that share the directory: see TRIVY_DATABASE_FILE.
    db_files = [
        item
        for item in cache_path.glob("**/*")
        if item.name == TRIVY_DATABASE_FILE and item.is_file()
    ]

    if not db_files:
        ASH_LOGGER.warning(
            f"Trivy offline mode: No database files found in cache directory: {cache_dir}"
        )
        messages.append(f"No database files found in cache directory: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # The registry's bound rather than the 7-day literal this used to carry, for the reason
    # given on the grype check above. This is still a file-mtime pre-check and still only a
    # warning; the authoritative check reads the database's own UpdatedAt after the scan
    # (utils/content_db_staleness.py) and fails the scan by default.
    trivy_max_age = get_content_database("trivy-db").max_age
    newest_db = max(db_files, key=lambda f: f.stat().st_mtime)
    db_age = _database_age(newest_db)

    if db_age > trivy_max_age:
        ASH_LOGGER.warning(
            f"Trivy offline mode: Database is {db_age.days} days old, past the "
            f"{go_duration(trivy_max_age)} bound trivy applies online; consider updating"
        )
        messages.append(
            f"Database is {db_age.days} days old, past the "
            f"{go_duration(trivy_max_age)} bound, consider updating"
        )
    else:
        ASH_LOGGER.info(
            f"Trivy offline mode: Found {len(db_files)} database files, newest is {db_age.days} days old"
        )
        messages.append(
            f"Found {len(db_files)} database files, newest is {db_age.days} days old"
        )

    return is_valid, messages


def validate_npm_audit_offline_mode() -> Tuple[bool, List[str]]:
    """
    Validate that npm audit offline mode requirements are met.

    Returns:
        Tuple of (is_valid, list_of_messages)
    """
    messages = []
    is_valid = True

    # Check for npm cache directory. npm reads its configuration variables in
    # the lowercase spelling (``npm_config_cache``) as well as the uppercase one;
    # on POSIX the two are different variables, and only the uppercase one was
    # read here.
    npm_cache_dirs = [
        os.environ.get("npm_config_cache") or os.environ.get("NPM_CONFIG_CACHE"),
        os.path.expanduser("~/.npm"),
        os.path.expanduser("~/AppData/Roaming/npm-cache"),  # Windows
        os.path.expanduser("~/Library/Caches/npm"),  # macOS
    ]

    cache_found = False
    for cache_dir in npm_cache_dirs:
        if cache_dir and Path(cache_dir).exists():
            cache_found = True
            ASH_LOGGER.info(f"npm audit offline mode: Found npm cache at {cache_dir}")
            messages.append(f"Found npm cache at {cache_dir}")
            break

    if not cache_found:
        ASH_LOGGER.warning("npm audit offline mode: No npm cache directory found")
        messages.append("No npm cache directory found")
        is_valid = False

    # Check for yarn cache if yarn is being used
    yarn_cache_dirs = [
        os.environ.get("YARN_CACHE_FOLDER"),
        os.path.expanduser("~/.yarn/cache"),
        os.path.expanduser("~/Library/Caches/Yarn"),  # macOS
        os.path.expanduser("~/AppData/Local/Yarn/Cache"),  # Windows
    ]

    for cache_dir in yarn_cache_dirs:
        if cache_dir and Path(cache_dir).exists():
            ASH_LOGGER.info(f"npm audit offline mode: Found yarn cache at {cache_dir}")
            messages.append(f"Found yarn cache at {cache_dir}")
            break

    return is_valid, messages


class OfflineModeValidator:
    """Helper class for consistent offline mode validation across scanners."""

    @staticmethod
    def validate_cache_directory(
        cache_dir: str, file_extensions: List[str], scanner_name: str
    ) -> Tuple[bool, List[str]]:
        """
        Generic cache directory validation.

        Args:
            cache_dir: Path to cache directory
            file_extensions: List of file extensions to look for
            scanner_name: Name of the scanner for logging

        Returns:
            Tuple of (is_valid, list_of_messages)
        """
        if not cache_dir:
            ASH_LOGGER.warning(
                f"{scanner_name} offline mode: Cache directory not specified"
            )
            return False, [f"{scanner_name} cache directory not specified"]

        # The same guard as the grype and trivy checks: a cache directory this
        # process may not search raised PermissionError out of Path.exists and
        # the glob, and the scanner's constructor with it.
        return _guarded(
            scanner_name,
            lambda: OfflineModeValidator._validate_cache_directory(
                cache_dir, file_extensions, scanner_name
            ),
        )

    @staticmethod
    def _validate_cache_directory(
        cache_dir: str, file_extensions: List[str], scanner_name: str
    ) -> Tuple[bool, List[str]]:
        messages = []
        is_valid = True

        cache_path = Path(cache_dir)
        if not cache_path.exists():
            ASH_LOGGER.warning(
                f"{scanner_name} offline mode: Cache directory does not exist: {cache_dir}"
            )
            messages.append(f"Cache directory does not exist: {cache_dir}")
            return False, messages

        # Check for files with specified extensions. Files only: a directory
        # whose name ends in the extension matched the glob and counted as a
        # cache file, so an empty cache passed.
        cache_files = []
        for ext in file_extensions:
            cache_files.extend(
                item for item in cache_path.glob(f"**/*{ext}") if item.is_file()
            )

        if not cache_files:
            ASH_LOGGER.warning(
                f"{scanner_name} offline mode: No cache files found with extensions {file_extensions}"
            )
            messages.append(f"No cache files found with extensions {file_extensions}")
            return False, messages

        ASH_LOGGER.info(
            f"{scanner_name} offline mode: Found {len(cache_files)} cache files"
        )
        messages.append(f"Found {len(cache_files)} cache files")

        return is_valid, messages

    @staticmethod
    def log_validation_results(scanner_name: str, is_valid: bool, messages: List[str]):
        """
        Log validation results in a consistent format.

        Args:
            scanner_name: Name of the scanner
            is_valid: Whether validation passed
            messages: List of validation messages
        """
        if is_valid:
            ASH_LOGGER.info(f"[OK] {scanner_name} offline mode validation passed")
        else:
            ASH_LOGGER.warning(
                f"[WARNING] {scanner_name} offline mode validation failed"
            )

        # Log each message
        for message in messages:
            if is_valid:
                ASH_LOGGER.info(f"  - {message}")
            else:
                ASH_LOGGER.warning(f"  - {message}")
