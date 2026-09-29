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
