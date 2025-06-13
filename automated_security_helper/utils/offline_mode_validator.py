"""Offline mode validation utilities for ASH scanners."""

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from automated_security_helper.utils.log import ASH_LOGGER


class OfflineModeValidator:
    """Helper class for validating offline mode requirements for scanners."""

    def __init__(self, scanner_name: str):
        """Initialize the validator for a specific scanner.

        Args:
            scanner_name: Name of the scanner (e.g., 'semgrep', 'grype', etc.)
        """
        self.scanner_name = scanner_name

    def validate_cache_directory(
        self,
        env_var_name: str,
        expected_file_patterns: Optional[List[str]] = None,
        min_files: int = 1,
    ) -> Tuple[bool, str, Dict[str, any]]:
        """Validate that a cache directory exists and contains expected files.

        Args:
            env_var_name: Environment variable name for the cache directory
            expected_file_patterns: List of file patterns to look for (e.g., ['*.yaml', '*.yml'])
            min_files: Minimum number of files expected in the cache

        Returns:
            Tuple of (is_valid, message, metadata)
        """
        cache_dir = os.environ.get(env_var_name)
        metadata = {
            "env_var": env_var_name,
            "cache_dir": cache_dir,
            "files_found": 0,
            "file_patterns": expected_file_patterns or [],
        }

        if not cache_dir:
            message = f"🔴 {self.scanner_name} offline mode: {env_var_name} environment variable not set"
            ASH_LOGGER.warning(message)
            return False, message, metadata

        cache_path = Path(cache_dir)
        if not cache_path.exists():
            message = f"🔴 {self.scanner_name} offline mode: Cache directory does not exist: {cache_dir}"
            ASH_LOGGER.warning(message)
            return False, message, metadata

        if not cache_path.is_dir():
            message = f"🔴 {self.scanner_name} offline mode: Cache path is not a directory: {cache_dir}"
            ASH_LOGGER.warning(message)
            return False, message, metadata

        # Count files matching patterns
        files_found = []
        if expected_file_patterns:
            for pattern in expected_file_patterns:
                files_found.extend(list(cache_path.glob(f"**/{pattern}")))
        else:
            # Count all files if no patterns specified
            files_found = list(cache_path.glob("**/*"))
            files_found = [f for f in files_found if f.is_file()]

        metadata["files_found"] = len(files_found)
        metadata["sample_files"] = [
            str(f.relative_to(cache_path)) for f in files_found[:5]
        ]

        if len(files_found) < min_files:
            message = f"🔴 {self.scanner_name} offline mode: Insufficient files in cache directory. Found {len(files_found)}, expected at least {min_files}"
            ASH_LOGGER.warning(message)
            return False, message, metadata

        message = f"✅ {self.scanner_name} offline mode: Cache directory validated with {len(files_found)} files"
        ASH_LOGGER.info(message)
        return True, message, metadata

    def validate_database_age(
        self, db_path: str, max_age_days: int = 30
    ) -> Tuple[bool, str, Dict[str, any]]:
        """Validate that a database file exists and is not too old.

        Args:
            db_path: Path to the database file
            max_age_days: Maximum age in days before warning

        Returns:
            Tuple of (is_valid, message, metadata)
        """
        from datetime import datetime

        metadata = {
            "db_path": db_path,
            "max_age_days": max_age_days,
            "exists": False,
            "age_days": None,
            "last_modified": None,
        }

        db_file = Path(db_path)
        if not db_file.exists():
            message = f"🔴 {self.scanner_name} offline mode: Database file does not exist: {db_path}"
            ASH_LOGGER.warning(message)
            return False, message, metadata

        metadata["exists"] = True

        # Check file age
        stat = db_file.stat()
        last_modified = datetime.fromtimestamp(stat.st_mtime)
        age = datetime.now() - last_modified
        age_days = age.days

        metadata["last_modified"] = last_modified.isoformat()
        metadata["age_days"] = age_days

        if age_days > max_age_days:
            message = f"⚠️ {self.scanner_name} offline mode: Database is {age_days} days old (last modified: {last_modified.strftime('%Y-%m-%d')}). Consider updating for latest vulnerability data."
            ASH_LOGGER.warning(message)
            return True, message, metadata  # Still valid, just old

        message = f"✅ {self.scanner_name} offline mode: Database is current ({age_days} days old)"
        ASH_LOGGER.info(message)
        return True, message, metadata

    def log_offline_mode_status(
        self, is_offline: bool, validations: List[Tuple[bool, str, Dict[str, any]]]
    ):
        """Log a comprehensive offline mode status for the scanner.

        Args:
            is_offline: Whether offline mode is enabled
            validations: List of validation results from validate_* methods
        """
        if not is_offline:
            ASH_LOGGER.info(f"🌐 {self.scanner_name}: Running in online mode")
            return

        ASH_LOGGER.info(f"📴 {self.scanner_name}: Running in offline mode")

        all_valid = True
        for is_valid, message, metadata in validations:
            if not is_valid:
                all_valid = False

        if all_valid:
            ASH_LOGGER.info(
                f"✅ {self.scanner_name}: All offline mode requirements satisfied"
            )
        else:
            ASH_LOGGER.warning(
                f"⚠️ {self.scanner_name}: Some offline mode requirements not met - scanner may fall back to defaults"
            )


def validate_semgrep_offline_mode() -> Tuple[bool, List[str]]:
    """Validate Semgrep offline mode requirements.

    Returns:
        Tuple of (all_requirements_met, list_of_messages)
    """
    validator = OfflineModeValidator("Semgrep")

    # Check for rules cache directory
    is_valid, message, metadata = validator.validate_cache_directory(
        "SEMGREP_RULES_CACHE_DIR",
        expected_file_patterns=["*.yaml", "*.yml"],
        min_files=1,
    )

    validator.log_offline_mode_status(True, [(is_valid, message, metadata)])

    return is_valid, [message]


def validate_grype_offline_mode() -> Tuple[bool, List[str]]:
    """Validate Grype offline mode requirements.

    Returns:
        Tuple of (all_requirements_met, list_of_messages)
    """
    validator = OfflineModeValidator("Grype")

    # Check for database cache directory
    db_cache_valid, db_message, db_metadata = validator.validate_cache_directory(
        "GRYPE_DB_CACHE_DIR", min_files=1
    )

    validations = [(db_cache_valid, db_message, db_metadata)]

    # If cache directory exists, check database age
    if db_cache_valid and db_metadata.get("cache_dir"):
        cache_dir = Path(db_metadata["cache_dir"])
        # Look for database files
        db_files = list(cache_dir.glob("**/*.db")) + list(
            cache_dir.glob("**/*vulnerability*")
        )
        if db_files:
            # Check the newest database file
            newest_db = max(db_files, key=lambda f: f.stat().st_mtime)
            age_valid, age_message, age_metadata = validator.validate_database_age(
                str(newest_db)
            )
            validations.append((age_valid, age_message, age_metadata))

    validator.log_offline_mode_status(True, validations)

    all_valid = all(valid for valid, _, _ in validations)
    messages = [msg for _, msg, _ in validations]

    return all_valid, messages


def validate_npm_audit_offline_mode() -> Tuple[bool, List[str]]:
    """Validate npm audit offline mode requirements.

    Returns:
        Tuple of (all_requirements_met, list_of_messages)
    """
    validator = OfflineModeValidator("npm-audit")

    # Check for npm cache
    npm_cache = os.environ.get("npm_config_cache") or os.path.expanduser("~/.npm")

    metadata = {
        "npm_cache": npm_cache,
        "cache_exists": Path(npm_cache).exists() if npm_cache else False,
    }

    if not npm_cache or not Path(npm_cache).exists():
        message = f"⚠️ npm-audit offline mode: npm cache directory not found at {npm_cache}. Offline mode may not work properly."
        ASH_LOGGER.warning(message)
        validator.log_offline_mode_status(True, [(False, message, metadata)])
        return False, [message]

    message = f"✅ npm-audit offline mode: npm cache directory found at {npm_cache}"
    ASH_LOGGER.info(message)
    validator.log_offline_mode_status(True, [(True, message, metadata)])

    return True, [message]


def validate_opengrep_offline_mode() -> Tuple[bool, List[str]]:
    """Validate Opengrep offline mode requirements.

    Returns:
        Tuple of (all_requirements_met, list_of_messages)
    """
    validator = OfflineModeValidator("Opengrep")

    # Check for rules cache directory
    is_valid, message, metadata = validator.validate_cache_directory(
        "OPENGREP_RULES_CACHE_DIR",
        expected_file_patterns=["*.yaml", "*.yml"],
        min_files=1,
    )

    validator.log_offline_mode_status(True, [(is_valid, message, metadata)])

    return is_valid, [message]
