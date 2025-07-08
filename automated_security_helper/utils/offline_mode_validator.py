# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline mode validation utilities for ASH scanners."""

import os
from pathlib import Path
from typing import List, Tuple
from datetime import datetime, timedelta

from automated_security_helper.utils.log import ASH_LOGGER


def validate_semgrep_offline_mode() -> Tuple[bool, List[str]]:
    """
    Validate that Semgrep offline mode requirements are met.

    Returns:
        Tuple of (is_valid, list_of_messages)
    """
    messages = []
    is_valid = True

    # Check for SEMGREP_RULES_CACHE_DIR environment variable
    cache_dir = os.environ.get("SEMGREP_RULES_CACHE_DIR")
    if not cache_dir:
        ASH_LOGGER.warning("Semgrep offline mode: SEMGREP_RULES_CACHE_DIR not set")
        messages.append("SEMGREP_RULES_CACHE_DIR environment variable not set")
        is_valid = False
        return is_valid, messages

    cache_path = Path(cache_dir)
    if not cache_path.exists():
        ASH_LOGGER.warning(
            f"Semgrep offline mode: Cache directory does not exist: {cache_dir}"
        )
        messages.append(f"Cache directory does not exist: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # Check for rule files in cache directory
    rule_files = [
        item
        for item in cache_path.glob("**/*")
        if item.is_file()
        and (item.name.endswith(".yaml") or item.name.endswith(".yml"))
    ]

    if not rule_files:
        ASH_LOGGER.warning(
            f"Semgrep offline mode: No rule files found in cache directory: {cache_dir}"
        )
        messages.append(f"No rule files found in cache directory: {cache_dir}")
        is_valid = False
        return is_valid, messages

    ASH_LOGGER.info(
        f"Semgrep offline mode: Found {len(rule_files)} rule files in cache"
    )
    messages.append(f"Found {len(rule_files)} rule files in cache directory")

    return is_valid, messages


def validate_opengrep_offline_mode() -> Tuple[bool, List[str]]:
    """
    Validate that Opengrep offline mode requirements are met.

    Returns:
        Tuple of (is_valid, list_of_messages)
    """
    messages = []
    is_valid = True

    # Check for OPENGREP_RULES_CACHE_DIR environment variable
    cache_dir = os.environ.get("OPENGREP_RULES_CACHE_DIR")
    if not cache_dir:
        ASH_LOGGER.warning("Opengrep offline mode: OPENGREP_RULES_CACHE_DIR not set")
        messages.append("OPENGREP_RULES_CACHE_DIR environment variable not set")
        is_valid = False
        return is_valid, messages

    cache_path = Path(cache_dir)
    if not cache_path.exists():
        ASH_LOGGER.warning(
            f"Opengrep offline mode: Cache directory does not exist: {cache_dir}"
        )
        messages.append(f"Cache directory does not exist: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # Check for rule files in cache directory
    rule_files = [
        item
        for item in cache_path.glob("**/*")
        if item.is_file()
        and (item.name.endswith(".yaml") or item.name.endswith(".yml"))
    ]

    if not rule_files:
        ASH_LOGGER.warning(
            f"Opengrep offline mode: No rule files found in cache directory: {cache_dir}"
        )
        messages.append(f"No rule files found in cache directory: {cache_dir}")
        is_valid = False
        return is_valid, messages

    ASH_LOGGER.info(
        f"Opengrep offline mode: Found {len(rule_files)} rule files in cache"
    )
    messages.append(f"Found {len(rule_files)} rule files in cache directory")

    return is_valid, messages


def validate_grype_offline_mode() -> Tuple[bool, List[str]]:
    """
    Validate that Grype offline mode requirements are met.

    Returns:
        Tuple of (is_valid, list_of_messages)
    """
    messages = []
    is_valid = True

    # Check for GRYPE_DB_CACHE_DIR environment variable
    cache_dir = os.environ.get("GRYPE_DB_CACHE_DIR")
    if not cache_dir:
        ASH_LOGGER.warning("Grype offline mode: GRYPE_DB_CACHE_DIR not set")
        messages.append("GRYPE_DB_CACHE_DIR environment variable not set")
        is_valid = False
        return is_valid, messages

    cache_path = Path(cache_dir)
    if not cache_path.exists():
        ASH_LOGGER.warning(
            f"Grype offline mode: Cache directory does not exist: {cache_dir}"
        )
        messages.append(f"Cache directory does not exist: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # Check for database files in cache directory
    db_files = [
        item
        for item in cache_path.glob("**/*")
        if item.is_file()
        and (
            item.name.endswith(".db")
            or item.name.endswith(".sqlite")
            or "vulnerability" in item.name.lower()
        )
    ]

    if not db_files:
        ASH_LOGGER.warning(
            f"Grype offline mode: No database files found in cache directory: {cache_dir}"
        )
        messages.append(f"No database files found in cache directory: {cache_dir}")
        is_valid = False
        return is_valid, messages

    # Check database age (warn if older than 7 days)
    newest_db = max(db_files, key=lambda f: f.stat().st_mtime)
    db_age = datetime.now() - datetime.fromtimestamp(newest_db.stat().st_mtime)

    if db_age > timedelta(days=7):
        ASH_LOGGER.warning(
            f"Grype offline mode: Database is {db_age.days} days old, consider updating"
        )
        messages.append(f"Database is {db_age.days} days old, consider updating")
    else:
        ASH_LOGGER.info(
            f"Grype offline mode: Found {len(db_files)} database files, newest is {db_age.days} days old"
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

    # Check for npm cache directory
    npm_cache_dirs = [
        os.environ.get("NPM_CONFIG_CACHE"),
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
        messages = []
        is_valid = True

        if not cache_dir:
            ASH_LOGGER.warning(
                f"{scanner_name} offline mode: Cache directory not specified"
            )
            messages.append(f"{scanner_name} cache directory not specified")
            return False, messages

        cache_path = Path(cache_dir)
        if not cache_path.exists():
            ASH_LOGGER.warning(
                f"{scanner_name} offline mode: Cache directory does not exist: {cache_dir}"
            )
            messages.append(f"Cache directory does not exist: {cache_dir}")
            return False, messages

        # Check for files with specified extensions
        cache_files = []
        for ext in file_extensions:
            cache_files.extend(cache_path.glob(f"**/*{ext}"))

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
            ASH_LOGGER.info(f"{scanner_name} offline mode validation passed")
        else:
            ASH_LOGGER.warning(f"{scanner_name} offline mode validation failed")

        for message in messages:
            ASH_LOGGER.info(f"  - {message}")
