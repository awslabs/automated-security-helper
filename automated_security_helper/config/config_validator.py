# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Configuration validation utilities for ASH."""

import json
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import yaml

from automated_security_helper.config.ash_config import load_config_yaml
from automated_security_helper.config.config_sources import (
    EXTENDS_KEY,
    PATCH_KEY,
    config_is_client_delivered,
    default_confinement_root,
    describe_config_path,
    named_text_stream,
    read_config_bytes,
    read_config_file,
    resolve_config_document,
)
from automated_security_helper.core.exceptions import (
    ASHConfigEnvNotResolvedError,
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
)
from automated_security_helper.utils.path_matching import directory_spelling


def directory_path_advice(path_pattern: str, *, ignore_path: bool) -> str:
    """The warning for a path that names an existing directory and no file in it.

    Shared by ``ash config validate`` and ``ash config lint``, and spelled as
    ``path_matching.directory_spelling`` spells it, as the warning after the scan
    does: ``<dir>/`` for an ignore path, ``<dir>/**/*`` for a suppression path.
    """
    spelling = directory_spelling(path_pattern, ignore_path=ignore_path)
    action = (
        "to ignore every file inside the directory"
        if ignore_path
        else "to suppress the findings in every file inside the directory"
    )
    return (
        f"Path '{path_pattern}' points to a directory but matches no file in it. "
        f"Use '{spelling}' {action}."
    )


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""


class ConfigValidator:
    """Validates ASH configuration files for common issues."""

    # Fields that should NOT appear in user configs (internal-only)
    INTERNAL_SCANNER_FIELDS = {
        "name",
        "extension",
        "tool_version",
        "install_timeout",
    }

    INTERNAL_REPORTER_FIELDS = {
        "name",
        "extension",
    }

    INTERNAL_CONVERTER_FIELDS = {
        "name",
        "tool_version",
        "install_timeout",
    }

    # Top-level fields that should NOT appear in user configs
    INVALID_TOP_LEVEL_FIELDS = {
        "build",
    }

    # Required top-level fields
    REQUIRED_TOP_LEVEL_FIELDS = {
        "project_name",
    }

    # Valid top-level fields
    VALID_TOP_LEVEL_FIELDS = {
        "project_name",
        "fail_on_findings",
        "fail_on_incomplete_scanners",
        "content_db_staleness",
        "content_db_staleness_overrides",
        "honor_ignore_files",
        "content_db_staleness_offline_image_default",
        "sandbox",
        "ash_plugin_modules",
        "external_reports_to_include",
        "global_settings",
        "scanners",
        "reporters",
        "converters",
        "mcp-resource-management",
        # Workspace-mode execution settings. Valid at the top level rather than
        # internal-only, because an operator scanning a multi-project workspace
        # sets max_parallel_projects and project_timeout by hand.
        "workspace",
        # Loader directives (#289), resolved before the config is validated.
        EXTENDS_KEY,
        PATCH_KEY,
    }

    # Prefix of every error about a config's `extends` chain or `patch`, which
    # ConfigLinter maps to its own category.
    EXTENDS_ERROR_PREFIX = "Config extends error: "

    # Prefix of the error for an `extends` base that `permit_base` refused. Its
    # own prefix so a caller can tell a refusal from a broken chain.
    NOT_PERMITTED_ERROR_PREFIX = "Config input not permitted: "

    # Prefix of the error for a config an MCP client delivered that uses !ENV,
    # which such a file may not; see "Environment variables" in config_sources.
    ENV_NOT_RESOLVED_ERROR_PREFIX = "Config refused, !ENV not resolved: "

    @classmethod
    def validate_config_file(
        cls,
        config_path: Path,
        source_dir: Optional[Path] = None,
        permit_base: Optional[Callable[[Path], bool]] = None,
        refuse_env: Optional[Callable[[Path], bool]] = None,
    ) -> Tuple[bool, List[str]]:
        """Validate a configuration file and return validation results.

        Args:
            config_path: Path to the configuration file
            source_dir: Path to the source directory (for resolving ignore_path patterns).
                        If None, inferred from config_path location.
            permit_base: Optional check every ``extends`` base must also pass;
                see ``config/config_sources.py``.
            refuse_env: Which files of the chain may not use ``!ENV``, as
                ``config_sources.resolve_config_document`` takes it. None refuses
                the files an MCP client delivered.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        config_path = Path(config_path)
        is_toml = config_path.name.endswith(".toml")
        raw_content = ""

        try:
            delivered = (refuse_env or config_is_client_delivered)(config_path)
            # Load the config file. YAML and JSON are parsed exactly as before;
            # TOML (an ashrc.toml, or pyproject.toml's [tool.ash] table) goes
            # through the loader's reader, which is the only TOML reader ASH has.
            # So does a file that may not use !ENV, so that a use of it is
            # reported as the refusal a scan of the file would meet. Without
            # !ENV the reader returns what yaml.safe_load and json.load would.
            if is_toml or delivered:
                try:
                    config_data = read_config_file(config_path, refuse_env=refuse_env)
                except ASHConfigEnvNotResolvedError as e:
                    errors.append(f"{cls.ENV_NOT_RESOLVED_ERROR_PREFIX}{e}")
                    return False, errors
                except ASHConfigSourceError as e:
                    errors.append(f"TOML error: {e}")
                    return False, errors
            else:
                # Read as a scan reads it: without blocking on a FIFO, only a
                # regular file, and at most ASH_CONFIG_MAX_FILE_BYTES.
                data = read_config_bytes(config_path)
                if str(config_path).endswith(".json"):
                    # utf-8-sig, as the loader reads JSON: a byte order mark is
                    # dropped.
                    raw_content = data.decode("utf-8-sig")
                    config_data = json.loads(raw_content)
                else:
                    raw_content = data.decode("utf-8")
                    config_data = load_config_yaml(
                        named_text_stream(raw_content, config_path)
                    )

            if not isinstance(config_data, dict):
                errors.append(
                    f"Configuration must be a dictionary/object, got {type(config_data).__name__}"
                )
                return False, errors

            # The file's own keys are what the field checks below look at, since
            # that is the file a fix would edit. Required fields and path
            # patterns are checked on the merged result, because a base may
            # supply them.
            resolved_data = config_data
            chain_resolved = True
            if EXTENDS_KEY in config_data or PATCH_KEY in config_data:
                try:
                    resolved_data = resolve_config_document(
                        config_path,
                        confine_to=default_confinement_root(config_path, source_dir),
                        permit_base=permit_base,
                        refuse_env=refuse_env,
                    ).data
                except ASHConfigInputNotPermittedError as e:
                    errors.append(f"{cls.NOT_PERMITTED_ERROR_PREFIX}{e}")
                    chain_resolved = False
                except ASHConfigEnvNotResolvedError as e:
                    # A base that may not use !ENV.
                    errors.append(f"{cls.ENV_NOT_RESOLVED_ERROR_PREFIX}{e}")
                    chain_resolved = False
                except ASHConfigSourceError as e:
                    errors.append(f"{cls.EXTENDS_ERROR_PREFIX}{e}")
                    chain_resolved = False
                if not isinstance(resolved_data, dict):
                    resolved_data = config_data

            # Check for required fields
            if chain_resolved:
                for field in cls.REQUIRED_TOP_LEVEL_FIELDS:
                    if field not in resolved_data:
                        errors.append(f"Missing required top-level field: '{field}'")

            # Check for invalid top-level fields
            for field in config_data.keys():
                if field in cls.INVALID_TOP_LEVEL_FIELDS:
                    errors.append(
                        f"Invalid top-level field '{field}' - this is an internal field and should not be in user configs"
                    )
                elif field not in cls.VALID_TOP_LEVEL_FIELDS:
                    errors.append(
                        f"Unknown top-level field '{field}' - may cause parsing issues"
                    )

            # Check for duplicate field definitions (YAML allows this but causes
            # issues). TOML rejects a duplicate key when it parses, and its
            # `key = value` lines would not be recognized here anyway, so for TOML
            # raw_content stays empty. The text is the one parsed above, not a
            # second read of the name.
            top_level_fields = {}
            for line in raw_content.split("\n"):
                stripped = line.strip()
                # Only consider lines with no leading whitespace (true top-level fields)
                if (
                    stripped
                    and not stripped.startswith("#")
                    and ":" in stripped
                    and not line[0].isspace()
                ):
                    field_name = stripped.split(":")[0].strip()
                    if field_name in cls.VALID_TOP_LEVEL_FIELDS:
                        if field_name in top_level_fields:
                            errors.append(
                                f"Duplicate top-level field '{field_name}' found at multiple locations"
                            )
                        top_level_fields[field_name] = True

            # Validate scanners section
            if "scanners" in config_data and isinstance(config_data["scanners"], dict):
                for scanner_name, scanner_config in config_data["scanners"].items():
                    if isinstance(scanner_config, dict):
                        for field in scanner_config.keys():
                            if field in cls.INTERNAL_SCANNER_FIELDS:
                                errors.append(
                                    f"Scanner '{scanner_name}' contains internal-only field '{field}' - "
                                    f"this should not be in user configs"
                                )

            # Validate reporters section
            if "reporters" in config_data and isinstance(
                config_data["reporters"], dict
            ):
                for reporter_name, reporter_config in config_data["reporters"].items():
                    if isinstance(reporter_config, dict):
                        for field in reporter_config.keys():
                            if field in cls.INTERNAL_REPORTER_FIELDS:
                                errors.append(
                                    f"Reporter '{reporter_name}' contains internal-only field '{field}' - "
                                    f"this should not be in user configs"
                                )

            # Validate converters section
            if "converters" in config_data and isinstance(
                config_data["converters"], dict
            ):
                for converter_name, converter_config in config_data[
                    "converters"
                ].items():
                    if isinstance(converter_config, dict):
                        for field in converter_config.keys():
                            if field in cls.INTERNAL_CONVERTER_FIELDS:
                                errors.append(
                                    f"Converter '{converter_name}' contains internal-only field '{field}' - "
                                    f"this should not be in user configs"
                                )

            # The names a scan refuses with exit 3, checked the same way and, like
            # the scan's check, without importing anything.
            plugin_modules_error = cls._plugin_modules_refusal(resolved_data)
            if plugin_modules_error is not None:
                errors.append(plugin_modules_error)

            # Validate ignore_paths and suppression paths for directory-without-glob issues
            warnings = cls._check_path_patterns(config_path, resolved_data, source_dir)
            errors.extend(warnings)

            return len(errors) == 0, errors

        except yaml.YAMLError as e:
            errors.append(f"YAML parsing error: {str(e)}")
            return False, errors
        except json.JSONDecodeError as e:
            errors.append(f"JSON parsing error: {str(e)}")
            return False, errors
        except Exception as e:
            errors.append(f"Unexpected error during validation: {str(e)}")
            return False, errors

    #: Prefix of the error for ``ash_plugin_modules`` names a scan refuses.
    PLUGIN_MODULES_ERROR_PREFIX = "Invalid ash_plugin_modules: "

    @classmethod
    def _plugin_modules_refusal(cls, config_data: dict) -> Optional[str]:
        """The scan's refusal of the config's ``ash_plugin_modules``, or None.

        Entries are split on commas and stripped the way a scan reads them, then
        given to ``plugins.loader.refuse_plugin_modules_outside_namespace``, which
        imports nothing. Whether an accepted name imports is not checked here.
        """
        from automated_security_helper.config.plugin_module_trust import (
            split_plugin_modules,
        )
        from automated_security_helper.plugins.loader import (
            PluginModuleError,
            refuse_plugin_modules_outside_namespace,
        )

        entries = config_data.get("ash_plugin_modules")
        if isinstance(entries, str):
            entries = [entries]
        if not isinstance(entries, (list, tuple)):
            return None
        try:
            refuse_plugin_modules_outside_namespace(split_plugin_modules(entries))
        except PluginModuleError as e:
            return f"{cls.PLUGIN_MODULES_ERROR_PREFIX}{e}"
        return None

    @classmethod
    def resolve_source_chain(
        cls, config_path: Path, source_dir: Optional[Path] = None
    ) -> List[str]:
        """Describe every file `config_path` is built from, lowest precedence first.

        Raises ``ASHConfigSourceError`` when the chain does not resolve.
        """
        config_path = Path(config_path)
        document = resolve_config_document(
            config_path, confine_to=default_confinement_root(config_path, source_dir)
        )
        return [describe_config_path(p) for p in document.chain]

    @classmethod
    def _check_path_patterns(
        cls,
        config_path: Path,
        config_data: dict,
        source_dir: Optional[Path] = None,
    ) -> List[str]:
        """Check ignore_paths and suppression paths for directory-without-glob issues.

        Returns a list of warning messages for paths that point to existing directories
        but lack a '**' glob suffix (meaning they won't match files inside).
        Only warns when the path actually exists as a directory in the repo.
        """
        warnings = []

        # Determine the project root for resolving relative paths
        if source_dir is not None:
            project_root = source_dir.resolve()
        else:
            config_parent = config_path.resolve().parent
            if config_parent.name == ".ash":
                project_root = config_parent.parent
            else:
                project_root = config_parent

        global_settings = config_data.get("global_settings", {})
        if not isinstance(global_settings, dict):
            return warnings

        # Check ignore_paths
        ignore_paths = global_settings.get("ignore_paths", [])
        if isinstance(ignore_paths, list):
            for entry in ignore_paths:
                if not isinstance(entry, dict):
                    continue
                path_pattern = entry.get("path", "")
                warning = cls._check_single_path(
                    path_pattern, project_root, ignore_path=True
                )
                if warning:
                    warnings.append(warning)

        # Check suppression paths
        suppressions = global_settings.get("suppressions", [])
        if isinstance(suppressions, list):
            for entry in suppressions:
                if not isinstance(entry, dict):
                    continue
                path_pattern = entry.get("path", "")
                warning = cls._check_single_path(
                    path_pattern, project_root, ignore_path=False
                )
                if warning:
                    warnings.append(warning)

        return warnings

    @classmethod
    def _check_single_path(
        cls, path_pattern: str, project_root: Path, *, ignore_path: bool
    ) -> Optional[str]:
        """Check a single path pattern for directory-without-glob issues.

        Returns a warning message if the path points to an existing directory and
        matches no file in it, or None if the path is fine. An ignore path ending
        in ``/`` names the directory and matches what is in it, so it is fine; a
        suppression path ending in ``/`` is literal and is not.
        """
        if not path_pattern:
            return None

        # Skip patterns that already contain ** (recursive glob)
        if "**" in path_pattern:
            return None
        if ignore_path and path_pattern.endswith(("/", "\\")):
            return None

        # Strip trailing slash for directory check
        clean_path = path_pattern.rstrip("/")

        # Skip patterns with wildcards in the filename portion
        from pathlib import PurePosixPath

        basename = PurePosixPath(clean_path).name
        if "*" in basename or "?" in basename or "[" in basename:
            return None

        # Check if this path resolves to an existing directory
        candidate = project_root / clean_path
        if candidate.is_dir():
            return directory_path_advice(path_pattern, ignore_path=ignore_path)

        return None

    @classmethod
    def validate_and_raise(cls, config_path: Path) -> None:
        """Validate a configuration file and raise an exception if invalid.

        Args:
            config_path: Path to the configuration file

        Raises:
            ConfigValidationError: If the configuration is invalid
        """
        is_valid, errors = cls.validate_config_file(config_path)

        if not is_valid:
            error_msg = f"Configuration validation failed for {config_path}:\n"
            for i, error in enumerate(errors, 1):
                error_msg += f"  {i}. {error}\n"
            error_msg += "\nPlease fix these issues and try again."
            error_msg += "\nTip: Run 'ash config validate' for detailed validation."
            raise ConfigValidationError(error_msg)
