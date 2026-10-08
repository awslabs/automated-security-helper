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


def ash_git_requirement(extra: str = "") -> str:
    """ASH as a PEP 508 direct reference to its own repository.

    ASH is installed from git, not from a package index, and the name
    ``automated-security-helper`` on PyPI belongs to an unrelated third party, so a
    requirement that names ASH without a URL resolves to a stranger's package.

    The reference is untagged. Pinning it to ``v<running version>`` was tried and
    rejected: a build of an unreleased version names a tag that does not exist yet,
    so the hint fails exactly where a developer reads it. The JetBrains plugin's
    install hint uses the same untagged URL.
    """
    name = (
        f"automated-security-helper[{extra}]" if extra else "automated-security-helper"
    )
    return f"{name} @ git+{ASH_REPO_URL}.git"


def ash_reinstall_command() -> str:
    """The command that reinstalls ASH from its repository."""
    return f'pip install --force-reinstall "{ash_git_requirement()}"'


def ash_extra_install_command(extra: str) -> str:
    """The command that adds one of ASH's optional extras to the running install.

    ASH is installed from git, not from a package index, and the name
    ``automated-security-helper`` on PyPI belongs to an unrelated third party. So a
    hint like ``pip install automated-security-helper[symbols]`` installs a
    stranger's package. This names ASH's own repository as a PEP 508 direct
    reference instead.
    """
    return f'pip install "{ash_git_requirement(extra)}"'


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
    -- ``ashx --help`` included -- and report it as an import error rather than as a
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

# Config sources discovered after ASH_CONFIG_FILE_NAMES, in this order. Both are
# read from the scan root only, never from ``.ash/``. The full precedence, and why
# the older names above still win when several sources exist, is documented in
# ``config/config_sources.py`` and docs/content/docs/configuration-guide.md.
ASH_RC_FILE_NAMES = [
    ".ashrc.toml",
    ".ashrc.yaml",
    ".ashrc.yml",
    ".ashrc.json",
    "ashrc.toml",
    "ashrc.yaml",
    "ashrc.yml",
    "ashrc.json",
]

# A pyproject.toml is a config source only when it has a [tool.ash] table.
ASH_PYPROJECT_FILE_NAME = "pyproject.toml"

# The discovery order in one sentence, for CLI help text.
#
# Written "the tool.ash table", not "[tool.ash]": every --help is rendered as rich
# markup, and rich reads "[tool.ash]" as a style tag and drops it, which printed
# "then a  table in pyproject.toml". The file-name lists survive only because a
# quoted, comma-separated list does not parse as a tag.
ASH_CONFIG_SOURCES_DESCRIPTION = (
    f"{ASH_CONFIG_FILE_NAMES} (each at the root, then in .ash/), then "
    f"{ASH_RC_FILE_NAMES} at the root, then the tool.ash table of "
    f"{ASH_PYPROJECT_FILE_NAME} at the root; the first found is used"
)

# Bounds on a config's `extends` chain. Depth counts the extending file as 0, so
# 10 allows ten levels of bases above it. The file count caps the total number of
# reads, which bounds a chain that fans out (every file extending several bases)
# where depth alone would not.
ASH_CONFIG_EXTENDS_MAX_DEPTH = 10
ASH_CONFIG_EXTENDS_MAX_FILES = 50

# The environment variable names an ASH config file may interpolate.
#
# Why there is a bound at all
# ---------------------------
# ``AshConfig.from_file`` resolves ``${VAR:default}`` references in YAML, and the
# file it resolves them in is the project config -- ``ASH_CONFIG_FILE_NAMES``
# above, found inside the tree being scanned. ASH's own use case is scanning code
# whose author is not the operator running the scan, so which variables that file
# may name is ASH's decision rather than the file's. Without a bound the set was
# "every variable in the process", and the resolved value does not stay in the
# field it lands in: ``AshAggregatedResults.ash_config`` holds the whole resolved
# config and ``to_simple_dict`` writes it into ``ash_aggregated_results.json``,
# so any field is an output field.
#
# This is the same reasoning ``config/ash_workspace_config.py`` records under
# "No ``!ENV`` substitution, unlike the project config", reached from the other
# direction. That loader answered the question by resolving nothing. This one
# cannot: the ``!ENV`` feature is deliberate, documented, and used by the AWS
# reporters, so the answer here is a bounded set rather than an empty one.
#
# Why a prefix plus a short list, rather than a list alone
# -------------------------------------------------------
# ASH's own settings are already conventionally ``ASH_``-prefixed, so a prefix
# covers every present and future one -- including the documented
# ``ASH_S3_BUCKET_NAME``, ``ASH_S3_BUCKET_PREFIX`` and
# ``ASH_CLOUDWATCH_LOG_GROUP`` -- without this list having to track the plugins.
# The three names below are the ones the shipped AWS reporters document that a
# prefix cannot reach.
#
# What was rejected
# -----------------
# * Interpolating for an operator-supplied ``--config`` but not for a config
#   discovered inside the scanned tree. The distinction exists in
#   ``resolve_config`` but does not track trust: pointing ``--config`` at a file
#   inside the tree is the documented common case, and ASH's own CI does it.
# * Dropping the implicit resolver so ``!ENV`` must be written explicitly. The
#   file is written by whoever wrote the tree, so they can write the tag too;
#   it would remove a working spelling and bound nothing.
# * An environment variable that extends this list. A bound an environment
#   variable can widen is not a bound -- ``ash_workspace_config.py`` records the
#   same objection about a ceiling -- and CI is where an extra variable is
#   easiest to arrange and hardest to notice.
#
# Growing the list
# ----------------
# Every entry names *where* to send a report, never *what to authenticate with*.
# ``tests/unit/config/test_config_env_interpolation.py`` asserts that, so an
# entry ending in KEY, TOKEN, SECRET, PASSWORD or CREDENTIAL fails the suite.
# An operator needing another name renames it with the ``ASH_`` prefix.
ASH_CONFIG_ENV_VAR_PREFIX = "ASH_"

ASH_CONFIG_ENV_VAR_ALLOWLIST = [
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
    "AWS_REGION",
]

# Dependency manifests, split by who writes them. The split is the whole point of
# these two lists and must not be undone -- see the failure mode at the bottom.
#
# WHY THE SPLIT EXISTS
# --------------------
# These names began as one list, KNOWN_LOCKFILE_NAMES, which the detect-secrets
# scanner used to drop files from its scan set *before* handing anything to
# detect-secrets. No comment, issue, or commit message anywhere in the history
# recorded a rationale; noise reduction is the only motive the code supports, and
# it is inferred rather than documented. The list also was not what its name said:
# requirements.txt, Pipfile and environment.yml are hand-written source files, not
# lock files, and the list carried no Cargo.lock, go.sum, composer.lock or
# Gemfile.lock.
#
# The cost of merging them was a silent blind spot. A credential embedded in a
# hand-authored declaration -- the classic case being a private index URL with
# inline basic-auth credentials, so an `--extra-index-url` whose host is preceded
# by a `user:token@` userinfo component, in requirements.txt, or the `[[source]]`
# url in a Pipfile -- was never scanned at all. Not suppressed, not baselined:
# never read. The pre-filter runs upstream of every other control, so no baseline
# `filters_used` entry, ignore-path setting or severity threshold could recover
# it, and nothing downstream re-adds a file.
#
# The userinfo above is deliberately written without a scheme in front of it.
# BasicAuthDetector matches `://` immediately followed by `word:word@`, so
# spelling the example out as a complete URL makes this comment a finding of the
# very scanner this change fixes -- which it was, until the wording moved the
# scheme off the line.
#
# The alternative was `# pragma: allowlist secret`, which detect-secrets honours
# inline and which would have let the full URL stay. It was not taken: that pragma
# allowlists the whole line against EVERY detector rather than against Basic Auth,
# and the literal shape is not lost by leaving it out of prose -- the fixture in
# tests/unit/plugin_modules/test_detect_secrets_lockfile_split.py spells the URL
# out in full, carries the pragma there, and is the place the shape is actually
# exercised rather than merely described.
#
# WHAT EACH SIDE COSTS
# --------------------
# Excluding the generated side buys quiet. A resolved lockfile is thousands of
# lines of integrity hashes, which is exactly the shape entropy detectors fire on,
# and a human never edits one -- so a finding in one is almost always noise, and
# the file is regenerated rather than repaired.
#
# Scanning the hand-authored side costs some false-positive risk and buys back the
# blind spot. The risk was measured rather than assumed: a `--require-hashes`
# pinned requirements.txt with 30+ `--hash=sha256:...` lines produces zero
# findings, because detect-secrets' own default heuristics already discount them.
#
# Most of the generated side is redundant with detect-secrets' own defaults --
# `heuristic.is_lock_file` matches package-lock.json, yarn.lock, poetry.lock and
# Pipfile.lock by basename, and `heuristic.is_non_text_file` drops any `.lock`
# extension, covering uv.lock and pipenv.lock. It is kept here anyway, because
# `Settings.configure_filters` *replaces* the default filter set with whatever a
# baseline's `filters_used` declares: a user who supplies a baseline loses
# is_lock_file unless they relist it. pnpm-lock.yaml, npm-shrinkwrap.json and
# conda-lock.* are not covered by detect-secrets at all, at any setting.
#
# FAILURE MODE -- DO NOT RE-MERGE THESE LISTS
# -------------------------------------------
# Re-merging reinstates the blind spot, and it does so invisibly: the scan still
# succeeds, still reports findings from every other file, and exits 0. There is no
# error, no warning, and no count that goes to zero -- the only symptom is a
# credential that is never mentioned. Adding a *hand-authored* name to the
# generated list has the same effect for that one filename. If a generated format
# is genuinely too noisy, add it to the generated list; never move a file a human
# types into it.

# Machine-generated, fully-resolved dependency locks. Excluded from secret
# scanning by default. Regenerated by their tool, never hand-edited, and dense
# with integrity hashes.
KNOWN_GENERATED_LOCKFILE_NAMES = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "poetry.lock",
    "uv.lock",
    "pipenv.lock",
    "conda-lock.yml",
    "conda-lock.yaml",
    "Pipfile.lock",
]

# Hand-authored dependency declarations. A human types these, so a credential can
# land in one, so they are scanned. Note that conda-environment.* and
# environment.* are environment *specifications*, not locks; conda-lock.* above is
# the generated counterpart.
KNOWN_DEPENDENCY_DECLARATION_NAMES = [
    "requirements.txt",
    "Pipfile",
    "environment.yml",
    "environment.yaml",
    "conda-environment.yml",
    "conda-environment.yaml",
]

# Deprecated compatibility alias, preserved because this is a published package and
# the name may be imported by out-of-tree plugins. It holds the original merged
# value so such an importer sees no change. Nothing inside ASH reads it, and
# nothing should: a scanner that filters on this list has the blind spot described
# above. Use one of the two lists it is built from.
KNOWN_LOCKFILE_NAMES = [
    *KNOWN_GENERATED_LOCKFILE_NAMES,
    *KNOWN_DEPENDENCY_DECLARATION_NAMES,
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
