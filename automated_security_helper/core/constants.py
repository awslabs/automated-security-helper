# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from pathlib import Path
from typing import Dict

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
ASH_DEFAULT_SEVERITY_LEVEL = os.environ.get("ASH_DEFAULT_SEVERITY_LEVEL", "MEDIUM")

ASH_CONFIG_FILE_NAMES = [
    ".ash.yml",
    ".ash.yaml",
    ".ash.json",
    "ash.yml",
    "ash.yaml",
    "ash.json",
]

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
# inline basic-auth credentials, e.g.
# `--extra-index-url https://user:token@pypi.example.com/simple` in
# requirements.txt, or the `[[source]]` url in a Pipfile -- was never scanned at
# all. Not suppressed, not baselined: never read. The pre-filter runs upstream of
# every other control, so no baseline `filters_used` entry, ignore-path setting or
# severity threshold could recover it, and nothing downstream re-adds a file.
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
