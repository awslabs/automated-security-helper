# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from pathlib import Path
from typing import Dict, Optional

from automated_security_helper.utils.severity_ladder import (
    SEVERITY_THRESHOLDS,
    normalize_threshold,
)

ASH_ASSETS_DIR = Path(__file__).parent.parent.joinpath("assets")
ASH_INSTALLED_REVISION_PATH = ASH_ASSETS_DIR.joinpath("ASH_INSTALLED_REVISION")
ASH_DOCS_URL = "https://awslabs.github.io/automated-security-helper"
ASH_REPO_URL = "https://github.com/awslabs/automated-security-helper"
ASH_REPO_LATEST_REVISION = (
    ASH_INSTALLED_REVISION_PATH.read_text().strip()
    if ASH_INSTALLED_REVISION_PATH.exists()
    else "v3.0.0-beta"
)

ASH_WORK_DIR_NAME = "converted"
ASH_BIN_PATH = (
    Path(os.environ["ASH_BIN_PATH"])
    if os.environ.get("ASH_BIN_PATH", None) is not None
    else Path.home().joinpath(".ash", "bin")
)
#: Used when ``ASH_DEFAULT_SEVERITY_LEVEL`` is unset or names no threshold. MEDIUM
#: is what ASH has always shipped, so an unusable value behaves as though the
#: variable were absent rather than moving the gate somewhere new.
_FALLBACK_SEVERITY_LEVEL = "MEDIUM"


def _resolve_default_severity_level(raw: Optional[str]) -> str:
    """Return a ladder threshold for *raw*, warning when it is not one.

    Why this is a function and not an ``os.environ.get`` with a default
    ---------------------------------------------------------------------
    The value becomes the default for ``global_settings.severity_threshold``, a
    ``Literal`` of the five ladder values -- and ``pydantic`` does not validate a
    default that no caller supplied. So an off-table environment value used to
    land in the field unchallenged, and the ladder reads an unrecognised threshold
    as CRITICAL. ``ASH_DEFAULT_SEVERITY_LEVEL=INFO``, which an operator would
    plausibly write meaning "report everything", therefore produced the strictest
    gate ASH has and dropped every finding below ``error`` from the verdict.
    Normalising here is what lets ``AshConfigGlobalSettingsSection`` assert its own
    default with ``validate_default=True``.

    Why it falls back rather than raising
    ------------------------------------
    This module is imported before anything can catch an exception from it, so
    raising would turn one mistyped variable into an ASH that cannot start at all
    -- ``ash --help`` included -- and report it as an import error rather than as a
    configuration problem. The fallback is announced at WARNING instead, which
    reaches stderr through ``logging.lastResort`` even this early in the process.

    Why the fallback is MEDIUM and not ALL
    -------------------------------------
    MEDIUM is the value ASH ships when the variable is unset, so an unrecognised
    value behaves exactly as though the operator had not set one -- the most
    reversible outcome, and the only one that cannot surprise a reader of the
    documented default. The junitxml reporter faces the same question about a
    threshold it cannot recognise and answers ALL, on the grounds that a reporter
    should show everything and let a human filter; that argument is about what to
    *display*, and a gate is not a display. Choosing ALL here would silently turn
    every informational finding in an adopter's tree into a build failure on
    upgrade, from a typo.
    """
    normalized = normalize_threshold(raw)
    if normalized is not None:
        return normalized

    if raw is not None:
        logging.getLogger(__name__).warning(
            "ASH_DEFAULT_SEVERITY_LEVEL=%r is not a severity threshold; falling "
            "back to %s. Valid values are: %s. Note that these name the least "
            "severe finding that still fails a scan, so they are not severity "
            "names -- there is no INFO or NONE threshold.",
            raw,
            _FALLBACK_SEVERITY_LEVEL,
            ", ".join(SEVERITY_THRESHOLDS),
        )
    return _FALLBACK_SEVERITY_LEVEL


ASH_DEFAULT_SEVERITY_LEVEL = _resolve_default_severity_level(
    os.environ.get("ASH_DEFAULT_SEVERITY_LEVEL")
)

ASH_CONFIG_FILE_NAMES = [
    ".ash.yml",
    ".ash.yaml",
    ".ash.json",
    "ash.yml",
    "ash.yaml",
    "ash.json",
]

KNOWN_LOCKFILE_NAMES = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "poetry.lock",
    "uv.lock",
    "pipenv.lock",
    "conda-lock.yml",
    "conda-lock.yaml",
    "conda-environment.yml",
    "conda-environment.yaml",
    "environment.yml",
    "environment.yaml",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
]

KNOWN_IGNORE_PATHS = [
    ".venv/",
    "venv/",
    "node_modules/",
]

KNOWN_SCANNABLE_EXTENSIONS = [
    # JavaScript and TypeScript ecosystem
    "js",
    "ts",
    "jsx",
    "tsx",
    # Scripting languages
    "py",
    "ipynb",
    "rb",
    "php",
    "pl",
    "pm",
    "t",
    # Systems programming languages
    "java",
    "go",
    "rs",
    "cpp",
    "c",
    "h",
    "hpp",
    "cs",
    # Apple development
    "m",
    "mm",
    "swift",
    # JVM languages
    "kt",
    "kts",
    "scala",
    "sc",
    "groovy",
    "gvy",
    "gradle",
    # Clojure ecosystem
    "clj",
    "cljs",
    "cljc",
    "edn",
    "cljx",
    # Other programming languages
    "dart",
    "r",
    # Database
    "sql",
    "tsql",
    # Shell scripting
    "sh",
    "bash",
    "zsh",
    "fish",
    "fsh",
    # Windows scripting
    "ps1",
    "psm1",
    "cmd",
    "bat",
    "vbs",
    "wsf",
    "wsh",
    # IaC Code
    "tf",
    "tfvars",
    "tfstate",
    "hcl",
    "json",
    "yaml",
    "yml",
    "xml",
    # Configuration
    "cfg",
    "conf",
    "ini",
    "properties",
    "env",
    "toml",
    # Markup
    "html",
    "htm",
    "xhtml",
    "svg",
    "md",
    "markdown",
    "rst",
    "adoc",
    "asciidoc",
    "asc",
    "txt",
    "text",
    "csv",
    "tsv",
    # # Data
    # "data",
    # "dat",
    # "db",
    # "sqlite",
    # "sqlite3",
    # "mdb",
    # "accdb",
    # "frm",
    # "ibd",
    # "myd",
    # "myi",
    # "ndb",
    # "sdf",
    # "sqlitedb",
    # "sqlite3db",
    # "sqlite3db",
    # "sqlite3db",
]
VALID_SEVERITY_VALUES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

ASH_EXIT_CODES: Dict[int, str] = {
    0: "success",
    1: "scan errors / scanner failures",
    2: "actionable findings above threshold",
    3: "invalid config",
    # 4 is workspace-mode only. It is deliberately NOT an overload of 2: a
    # workspace definition error means nothing was scanned, whereas 2 means a
    # scan completed and found something. See models/workspace.py for why the
    # RFC's original assignment of 2 was not used.
    4: "workspace definition or policy error",
}


def is_offline_mode() -> bool:
    """Check if ASH is running in offline mode via ASH_OFFLINE env var."""
    return str(os.environ.get("ASH_OFFLINE", "NO")).upper() in ["YES", "TRUE", "1"]
