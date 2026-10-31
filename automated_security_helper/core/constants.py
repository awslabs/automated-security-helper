# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import re
import threading
from pathlib import Path, PurePath
from typing import Any, Dict, List, Optional, Set, Tuple

from automated_security_helper.utils.severity_ladder import (
    SEVERITY_THRESHOLDS,
    normalize_threshold,
)

ASH_ASSETS_DIR = Path(__file__).parent.parent.joinpath("assets")
ASH_INSTALLED_REVISION_PATH = ASH_ASSETS_DIR.joinpath("ASH_INSTALLED_REVISION")
ASH_DOCS_URL = "https://awslabs.github.io/automated-security-helper"
ASH_REPO_URL = "https://github.com/awslabs/automated-security-helper"


def _installed_revision(path: Path) -> str:
    """The commit the package was built from, as hatch_build.py recorded it.

    Without the asset (a tree that was never built) nothing is recorded, which
    reads the same as the build's own "unknown-commit", and never as a real tag
    that a container build would then install. A path that cannot even be
    checked or read (a stat or read the OS refuses) reads as absent too: this
    runs at import time, ``Path.exists()`` can propagate the refused stat's
    OSError (measured: 3.10 through 3.13 raise PermissionError, 3.14 answers
    False), and ``read_text()`` raises it on every interpreter, so without
    the handler an uncheckable install location kills ``import ash``. The
    handler is live on every supported version, not a versioned shim.

    An asset that does not decode (``UnicodeDecodeError`` is a ``ValueError``,
    not an ``OSError``) reads as absent too: it was read with the locale's codec,
    and an asset that is not text would otherwise kill the import the same way.
    The build writes the revision as UTF-8.
    """
    try:
        if not path.exists():
            return "unknown-commit"
        return path.read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return "unknown-commit"


ASH_REPO_LATEST_REVISION = _installed_revision(ASH_INSTALLED_REVISION_PATH)

ASH_WORK_DIR_NAME = "converted"
#: The ``skipped_reason`` of a scanner a ``--python-only`` run leaves out. One
#: spelling, because ``ash merge`` reads it back to tell a scanner the flag left out
#: from one no shard was asked to run.
PYTHON_ONLY_SKIPPED_REASON = "not a Python-only scanner, and --python-only is set"
#: The start of the ``excluded_reason`` the scan phase records for a scanner that
#: a sharded run assigned to another shard; the shard index and count follow it.
#: One spelling, for the same reason as above: ``ash merge`` matches this prefix to
#: tell a scanner the split left out from one no shard was asked to run, so a
#: reword here that the merge did not follow would reopen that hole silently.
SHARD_SPLIT_REASON_PREFIX = "assigned to another shard (this run is shard "


def is_anchored(path: str, pathmod: Any = os.path) -> bool:
    """Whether ``path`` names a location without reference to the cwd.

    ``isabs`` alone is not enough on Windows: before Python 3.13 ``\\tools`` counts
    as absolute there, but it is rooted on whichever drive is current. A drive
    letter or UNC share is required as well.
    """
    if not pathmod.isabs(path):
        return False
    if pathmod.__name__ == "ntpath":
        return bool(pathmod.splitdrive(path)[0])
    return True


#: The (variable, value) pairs from the environment already warned about in this
#: process.
_warned_relative_values: Set[Tuple[str, str]] = set()
#: Orders the check and the add below: two threads that both read "not warned
#: yet" each logged the once-only warning.
_warned_relative_values_lock = threading.Lock()


def warn_relative_value_once(variable: str, value: str, message: str) -> None:
    """Log ``message`` the first time ``variable``'s relative ``value`` is ignored in
    this process.

    Keyed by the variable as well as the value: the same value in two variables is
    two settings to fix, and each one's warning names it.
    """
    key = (variable, value)
    with _warned_relative_values_lock:
        if key in _warned_relative_values:
            return
        _warned_relative_values.add(key)
    from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP

    ASH_LOGGER.warning(message, extra=NO_MARKUP)


def usable_home() -> Optional[Path]:
    """The home directory, when it names its location by itself; else None.

    The one place ASH decides whether there is a home directory: every path it
    builds under ``~`` comes from here, through :func:`expand_home` and
    :func:`xdg_directory` where those fit
    (tests/unit/core/test_home_paths_go_through_usable_home.py checks).

    On POSIX it is HOME when HOME is set, not empty, and absolute. When HOME is
    unset it is the passwd entry's home directory, if that is absolute, as
    ``os.path.expanduser`` falls back too: the system's user database is outside
    the scanned repository's control. A HOME that is set wins over the passwd
    entry, so an empty HOME, which makes ``~`` the filesystem root, and a relative
    one, which names a directory under the working directory (usually the
    repository being scanned), give None, as does an unset HOME with no absolute
    passwd home. A HOME that is the filesystem root itself (``/``, which Docker
    sets for a ``--user`` with no passwd entry) names no home either: ``~/.ash/bin``
    would be ``/.ash/bin`` and the caches would sit at the top of the filesystem,
    the same place an empty HOME led to. On Windows it is the home directory
    ``os.path.expanduser`` finds (USERPROFILE, or HOMEDRIVE and HOMEPATH), when
    that has a drive or share and is not a drive's root.
    """
    if os.name == "nt":
        home = os.path.expanduser("~")
        if home == "~" or not is_anchored(home) or _is_filesystem_root(home):
            return None
        return Path(home)
    value = os.environ.get("HOME")
    if value is None:
        try:
            import pwd

            value = pwd.getpwuid(os.getuid()).pw_dir
        except (ImportError, KeyError, AttributeError, OSError):
            return None
    if not value or not is_anchored(value) or _is_filesystem_root(value):
        return None
    return Path(value)


def _is_filesystem_root(value: str) -> bool:
    """Whether *value* is a root (``/``, ``//``, ``C:\\``): a path with no parent."""
    path = Path(value)
    return path.parent == path


def _names_the_home(value: str) -> bool:
    """Whether *value* is ``~`` alone or starts ``~/`` (``~\\`` too on Windows)."""
    separators = ("/", "\\") if os.name == "nt" else ("/",)
    return value == "~" or value.startswith(tuple("~" + sep for sep in separators))


def expand_home(value: str, *, warn: bool = True) -> Optional[str]:
    """``value`` with a leading ``~`` expanded to :func:`usable_home`.

    ``~`` alone and ``~/...`` (``~\\...`` too on Windows) need the home directory,
    and give None when there is no usable one: the caller decides whether that
    drops the value, refuses, or keeps it as written. Any other value, ``~user``
    included, is returned as ``os.path.expanduser`` returns it. ``warn=False``
    gives None without the warning about the unusable home.
    """
    if _names_the_home(value):
        home = usable_home()
        if home is None:
            if warn:
                warn_if_home_unusable()
            return None
        return str(home) + value[1:]
    return os.path.expanduser(value)


def xdg_directory(variable: str, *under_home: str) -> Optional[Path]:
    """An XDG base directory: ``variable``'s value, or ``~/<under_home>``.

    The value is used only when it is absolute: the XDG Base Directory
    specification says a relative path in one of these variables is invalid and is
    ignored. The default under the home directory is None when there is no usable
    home (:func:`usable_home`).
    """
    value = os.environ.get(variable, "")
    if value and is_anchored(value):
        return Path(value)
    home = usable_home()
    if home is None:
        warn_if_home_unusable()
        return None
    return home.joinpath(*under_home)


def warn_if_home_unusable() -> None:
    """Say, once per value, that nothing under ``~`` is used for an unusable HOME."""
    if usable_home() is not None:
        return
    variable = "USERPROFILE" if os.name == "nt" else "HOME"
    value = os.environ.get(variable)
    if value is None:
        described = (
            "not set, and HOMEDRIVE and HOMEPATH name no absolute home directory"
            if os.name == "nt"
            else "not set, and the passwd entry names no absolute home directory"
        )
    elif not value:
        described = "empty"
    elif is_anchored(value):
        # Anchored, yet no home: only a filesystem root is refused after that.
        described = "the filesystem root"
    elif os.name == "nt":
        described = "not an absolute path"
    else:
        described = f"the relative path {value!r}"
    advice = "an absolute path" + (
        " other than the filesystem root" if described == "the filesystem root" else ""
    )
    # An unset variable and an empty one are two settings with two messages, so
    # they are keyed apart: the empty string stood for both, and the second
    # warning in a process was suppressed. A NUL cannot be in an environment value.
    warn_relative_value_once(
        variable,
        "\x00unset" if value is None else value,
        f"{variable} is {described}, so ASH uses nothing under ~: no tools in "
        "~/.ash/bin, no install receipts, no caches, and no scanner sandbox. A "
        "relative home would name a directory under the working directory, usually "
        f"the repository being scanned. Set {variable} to {advice}.",
    )


def home_bin_path() -> Optional[Path]:
    """``~/.ash/bin``, when there is a usable home directory (:func:`usable_home`)."""
    home = usable_home()
    return None if home is None else home.joinpath(".ash", "bin")


def is_blank_bin_path(value: "str | None") -> bool:
    """True when ``value`` names no directory: unset, empty, or only blanks.

    Path("") is the working directory and Path(" ") a directory named " " under
    it, so either made the install write into the repository it ran in and every
    lookup search it. Path() also drops a trailing separator, which made "  /" the
    relative "  ". So a value is blank when it is only whitespace or when every
    component Path() keeps is: "  /", " /" and "\\t/" are blank. "/" and "." name
    a directory, and so does " /x", a relative path, so they are not blank. Tool
    lookup does not search a relative ASH_BIN_PATH (subprocess_utils.find_executable),
    and ``ash dependencies install`` makes a relative bin path absolute.
    """
    if not value or not value.strip():
        return True
    parts = PurePath(value).parts
    return bool(parts) and not any(part.strip() for part in parts)


def ash_bin_path_from_environment(warn: bool = True) -> "str | None":
    """ASH_BIN_PATH as set, or None when it is unset or blank (is_blank_bin_path).

    The one reading of the variable. A value a shell left unexpanded (``~`` or
    ``~/bin``, from a quoted assignment or a Windows ``set``) is expanded from the
    usable home (:func:`usable_home`), as ``ash dependencies install`` expands the
    same value to choose where it installs. Read literally it was a relative path,
    which tool lookup does not search, so what the install put in the expanded
    directory was never found by a later scan. With no usable home the value
    names nowhere, and reads as unset.

    ``warn=False`` reads the value without saying so when the home is unusable.
    The module reads it that way while it is being imported, before the logging
    that carries the warning is set up: a once-only warning raised then is spent
    where nobody reads it, and the scan-time readers, which do warn, then stay
    silent.
    """
    value = os.environ.get("ASH_BIN_PATH")
    if value is None or is_blank_bin_path(value):
        return None
    if _names_the_home(value):
        return expand_home(value, warn=warn)
    return value


def _bin_path_at_import() -> Optional[Path]:
    """ASH_BIN_PATH as set (:func:`ash_bin_path_from_environment`), else
    ``~/.ash/bin`` when there is a usable home directory (:func:`home_bin_path`),
    else None: ASH then has no bin directory, and tools are found through PATH
    alone. An empty or relative HOME gives no ``~/.ash/bin``, since it would name
    the filesystem root's or a directory under the working directory.

    It warns about nothing: this runs while the module is imported, and the callers
    that read the variable during a run warn about an unusable home themselves.
    """
    from_environment = ash_bin_path_from_environment(warn=False)
    return Path(from_environment) if from_environment else home_bin_path()


ASH_BIN_PATH: Optional[Path] = _bin_path_at_import()
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

    # An empty or blank value is an unset one: a shell that exports the name with
    # nothing after it (``ASH_DEFAULT_SEVERITY_LEVEL=``) chose no threshold, and
    # warning that it "is not a severity threshold" repeated on every start.
    if raw is not None and raw.strip():
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

# The name every ASH command that creates a config file gives it: `ash config
# init` and `ash config wizard` with no --config, and `ash inspect findings` when
# no config exists yet. Discovery reads ASH_RC_FILE_NAMES and [tool.ash] after
# ASH_CONFIG_FILE_NAMES, and its warning calls the older names deprecated (#313),
# so a new file gets a name from ASH_RC_FILE_NAMES. Of those, the first YAML one:
# these commands write YAML and refuse TOML. Existing files under the older names
# keep loading, and keep winning over this one when both exist, which is why the
# commands refuse to create it next to another source.
ASH_DEFAULT_CONFIG_FILE_NAME = ".ashrc.yaml"

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

# The most ASH reads from one config file: 1 MiB. A config is text a person edits;
# ASH's own .ash/.ash.yaml is about 160 KiB, so this is six times that. The bound
# stops a file, or a device at a config name, from being read into memory without
# limit, and it bounds what parsing one costs: a flat 15 MiB YAML list took about
# 230 s and 4.3 GiB to resolve, where 1 MiB takes a fraction of that. It does not
# bound YAML aliases, which expand after parsing; the config loaders refuse those
# (see load_config_yaml in config/ash_config.py).
ASH_CONFIG_MAX_FILE_BYTES = 1024 * 1024

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
# entry ending in KEY, TOKEN, SECRET, PASSWORD, CREDENTIAL or HEADER_VALUE fails
# the suite.
# An operator needing another name renames it with the ``ASH_`` prefix.
#
# A config file an MCP client delivered is outside this bound altogether: it may
# not use ``!ENV`` at all, and is refused if it does. See "Environment
# variables" in ``config/config_sources.py``.
ASH_CONFIG_ENV_VAR_PREFIX = "ASH_"

ASH_CONFIG_ENV_VAR_ALLOWLIST = [
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
    "AWS_REGION",
]

# ``ASH_`` names a config file may not interpolate whatever they hold: a name
# that ends, compared case-insensitively, in one of these suffixes, and the
# names listed after them. The prefix admits every ``ASH_`` variable in the
# process, including ones an operator or a wrapper exports for a credential:
# ``ASH_MCP_AUTH_HEADER_VALUE`` is the documented one, which ash-mcp-serve and
# ash-container-init take out of the environment before ASH starts because a
# config could read it. A reference to one of these names is left as written,
# as a reference to an unlisted name is.
#
# The suffixes are the plain ends-with reading only. The one rule for a
# config loader is :func:`is_refused_config_environment_name`, which reads
# these, the names below, and the module's own secret-shaped reading
# (:func:`is_secret_shaped_environment_name`). On a tree whose loader
# (config/ash_config.py, ``config_env_var_is_secret_shaped``) returns this
# rule's answer, a name the masking rule classes as holding a secret is one a
# config file may not read; on a tree whose loader still reads this tuple and
# the names below alone, only those two readings apply to a config file. The
# tuple was widened before the loader was pointed at the rule, so that it
# alone already covered the words the masking rule names (until then a config
# file inside the scanned tree could interpolate ASH_DB_PASS, ASH_GITHUB_PAT,
# ASH_API_KEY_PROD, ASH_API_KEY2, ASH_APIKEY or ASH_X_PASSPHRASE, every one of
# them a name the masking rule classes as holding a secret). The one rule reads
# ``ASH_CONFIG_ENV_VAR_READABLE_NAMES`` (below) before this tuple and before
# the masking reading, so the one named setting that ends in a word here
# (``ASH_BEDROCK_MAX_TOKENS``) is admitted while every other such name stays
# refused.
ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES = (
    "_KEY",
    "_KEYS",
    "_TOKEN",
    "_TOKENS",
    "_SECRET",
    "_SECRETS",
    "_PASSWORD",
    "_PASSWORDS",
    "_PASSWD",
    "_PASSWDS",
    "_PASS",
    "_PASSES",
    "_PASSPHRASE",
    "_PASSPHRASES",
    "_PWD",
    "_PWDS",
    "_PAT",
    "_PATS",
    "_AUTH",
    "_AUTHS",
    "_AUTHORIZATION",
    "_AUTHORIZATIONS",
    "_CREDENTIAL",
    "_CREDENTIALS",
    "_HEADER_VALUE",
)
ASH_CONFIG_ENV_VAR_SECRET_NAMES = ("ASH_MCP_AUTH_HEADER_VALUE",)

# ``ASH_`` names a config file MAY interpolate although they end in a listed
# suffix, each named exactly: a limit named after the word, not the word's
# value. The one such setting ASH reads is ``ASH_BEDROCK_MAX_TOKENS``
# (``max_tokens`` of the Bedrock summary reporter), which ``_TOKENS`` would
# refuse. :func:`is_refused_config_environment_name` reads these before the
# suffixes and before the masking rule's reading, compared case-insensitively.
# Names, not a suffix: a suffix allow (``_MAX_TOKENS``) also admitted
# ``ASH_API_KEY_MAX_TOKENS`` and every other name an operator exports under that
# ending, so a name here is admitted and nothing else is; ``ASH_X_MAX_TOKENS``,
# ``ASH_API_KEY_MAX_TOKENS``, a plural token name without the limit word
# (``ASH_API_TOKENS``, ``ASH_X_TOKENS``) and the singular ``ASH_MAX_TOKEN`` all
# stay refused. A new limit setting is added here by name, with its reader.
ASH_CONFIG_ENV_VAR_READABLE_NAMES = ("ASH_BEDROCK_MAX_TOKENS",)


def is_refused_config_environment_name(name: str) -> bool:
    """Whether a config file may NOT interpolate the ``ASH_`` variable *name*,
    whatever it holds: the one name rule for the config loader's ``!ENV``
    exclusion.

    True for a listed name (``ASH_CONFIG_ENV_VAR_SECRET_NAMES``), a name ending
    in one of ``ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES``, and any name
    :func:`is_secret_shaped_environment_name` classes as holding a secret, read
    case-insensitively. The three readings used to be two: the loader applied
    the suffixes and the names, while the secret-shaped reading masked the
    stream output only, so the loader admitted names the same module called
    secrets (qualified, glued and digit-suffixed forms among them).

    False, before the suffixes and the masking rule's reading, for a name
    listed in ``ASH_CONFIG_ENV_VAR_READABLE_NAMES``: the one limit setting
    named after a word (``ASH_BEDROCK_MAX_TOKENS``), which both readings would
    otherwise refuse for its plural ``TOKENS``. By exact name, so no other name
    ending the same way (``ASH_API_KEY_MAX_TOKENS``) rides on it. The listed
    secret names come first still.
    """
    upper = name.upper()
    if upper in ASH_CONFIG_ENV_VAR_SECRET_NAMES:
        return True
    if upper in ASH_CONFIG_ENV_VAR_READABLE_NAMES:
        return False
    return upper.endswith(
        ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES
    ) or is_secret_shaped_environment_name(name)


def is_readable_environment_name(name: str) -> bool:
    """Whether a config file may read the environment variable *name*.

    The one name rule: a name beginning with ``ASH_CONFIG_ENV_VAR_PREFIX`` or
    listed in ``ASH_CONFIG_ENV_VAR_ALLOWLIST``, compared exactly as written.
    The config loader's resolution and the container runner's list of values to
    hide both call it, so the two cannot drift.
    """
    return (
        name.startswith(ASH_CONFIG_ENV_VAR_PREFIX)
        or name in ASH_CONFIG_ENV_VAR_ALLOWLIST
    )


#: Variable-name words that name what to authenticate with, never where to
#: send a report. The allowlist above holds no such name, but any ``ASH_``
#: name is readable, so ``ASH_API_TOKEN`` is a name a config can read. The set
#: is wider than the five singular forms the allowlist test bars (KEY, TOKEN,
#: SECRET, PASSWORD, CREDENTIAL): a name outside those forms can still carry a
#: secret (``ASH_X_CREDENTIALS``, ``ASH_X_DB_PASS``).
#:
#: Over-masking damages a report; under-masking prints a secret, so the rule
#: errs toward matching where a name is about a secret. :func:`is_secret_shaped_environment_name`
#: reads every entry two ways: the name ends with it (``GITHUBTOKEN``,
#: ``MONKEY``), and the entry is a run of whole ``_``/``-`` separated segments
#: followed only by trailing qualifiers (``API_KEY_PROD``, ``DB_PASSWORD_2``).
#: A name whose later segments say something else (``AUTH_ENABLED``,
#: ``PASS_THRESHOLD``: a flag or a limit named after the word, not the word's
#: value) is not matched by that reading. The one exception to the ends-with
#: reading is the explicit denylist ``SECRET_SHAPED_FALSE_POSITIVE_SEGMENTS``
#: below.
SECRET_SHAPED_NAME_SUFFIXES = (
    "KEY",
    "KEYS",
    "TOKEN",
    "TOKENS",
    "SECRET",
    "SECRETS",
    "PASSWORD",
    "PASSWORDS",
    "CREDENTIAL",
    "CREDENTIALS",
    "PASS",
    "PASSES",
    "PASSWD",
    "PASSWDS",
    "PWD",
    "PWDS",
    "PAT",
    "PATS",
    "AUTH",
    "AUTHS",
    "AUTHORIZATION",
    "AUTHORIZATIONS",
    "PASSPHRASE",
    "PASSPHRASES",
)

#: The names that are not secret-shaped although they end with a listed word.
#: Each is a whole segment, compared by equality, never by substring or suffix,
#: and each is listed with the measurement that put it here: a name an earlier
#: review measured as a false positive of the plain ends-with test.
#:
#: - ``COMPAT``: ends with ``PAT``
#: - ``BYPASS``: ends with ``PASS``
#: - ``COMPASS``: ends with ``PASS``
#: - ``OLDPWD``: ends with ``PWD`` (the shell's previous directory)
#:
#: A name whose last segment equals one of these is not matched by the
#: ends-with reading (``ASH_COMPAT``); ``BYPASS_TOKEN`` and ``MYCOMPASS_TOKEN``
#: stay strict because their last segment is ``TOKEN``. The compare also reads
#: the segment's plural and digit-qualified spellings (``BYPASSES``,
#: ``BYPASS2``): the plural suffix or digit run is stripped before the
#: equality test, rather than listing every such spelling as its own member.
#: The list grows only with a new measurement and the maintainers' approval.
SECRET_SHAPED_FALSE_POSITIVE_SEGMENTS = ("COMPAT", "BYPASS", "COMPASS", "OLDPWD")


#: A trailing qualifier: what a name may append after its secret word without
#: changing what the word says the name holds. A digit run, a version mark,
#: or a deployment-stage word. The segment-run reading accepts a match only
#: when every segment after the run is one of these, so ``ASH_API_KEY_PROD``
#: is secret-shaped and ``ASH_AUTH_ENABLED`` (a flag named after the word, not
#: the word's value) is not.
_TRAILING_QUALIFIER_SEGMENT = re.compile(r"\d+|V\d+|PROD|STAGING|DEV|TEST")

#: A qualifier glued straight onto a secret word inside one segment, read
#: after the segment's trailing digits are stripped, so ``V2`` reads ``V``
#: here and a bare digit run is already gone.
_GLUED_QUALIFIER = re.compile(r"V|PROD|STAGING|DEV|TEST")

#: The same qualifiers at the end of a segment, for a secret word the segment
#: ends with and does not begin with (``GITHUBTOKENPROD``).
_GLUED_QUALIFIER_AT_END = re.compile(r"(?:V|PROD|STAGING|DEV|TEST)$")

#: A segment's trailing digit run: ``KEY2`` and ``PASSWORD1`` carry the same
#: words as ``KEY`` and ``PASSWORD``.
_TRAILING_DIGITS = re.compile(r"\d+$")
_LEADING_DIGITS = re.compile(r"^[0-9]+")


def _canonical_segment(segment: str) -> str:
    """*segment* with its trailing digits stripped, then with a glued trailing
    qualifier stripped where the remainder is a listed secret word, so
    ``KEY2`` reads ``KEY`` and ``TOKENPROD`` reads ``TOKEN``. Any other
    segment comes back digit-stripped only (``ENABLED``, ``PASSPORT``)."""
    stripped = _TRAILING_DIGITS.sub("", segment)
    for entry in SECRET_SHAPED_NAME_SUFFIXES:
        # The qualifier may follow digits that sit between the word and it
        # (``KEY2PROD``, ``TOKEN1DEV``): those digits are not a trailing run, so
        # they are skipped before the qualifier is read.
        rest = _LEADING_DIGITS.sub("", stripped[len(entry) :])
        if stripped.startswith(entry) and rest and _GLUED_QUALIFIER.fullmatch(rest):
            return entry
    # A qualifier glued after a word the segment ENDS with, not begins with:
    # ``GITHUBTOKENPROD`` reads ``GITHUBTOKEN`` and ``MYPASSWORDV2`` reads
    # ``MYPASSWORD``, which the ends-with reading then matches as it matches the
    # unqualified names.
    glued = _GLUED_QUALIFIER_AT_END.search(stripped)
    if glued is not None and glued.start() > 0:
        head = _TRAILING_DIGITS.sub("", stripped[: glued.start()])
        if head.endswith(SECRET_SHAPED_NAME_SUFFIXES):
            return head
    return stripped


def _is_trailing_qualifier(segment: str) -> bool:
    """Whether *segment* is a trailing qualifier, read as written and with its
    trailing digit run stripped: ``PROD``, ``2`` and ``V2`` as before, and
    ``PROD2`` (a stage word glued to a digit run) too, which the written-form
    test alone did not read, contrary to the documented contract."""
    if _TRAILING_QUALIFIER_SEGMENT.fullmatch(segment):
        return True
    stripped = _TRAILING_DIGITS.sub("", segment)
    return not stripped or bool(_GLUED_QUALIFIER.fullmatch(stripped))


def _is_false_positive_segment(segment: str) -> bool:
    """Whether *segment* is denylisted, read with its plural spellings:
    ``BYPASSES`` and ``COMPATS`` are the plurals of denylisted segments, so a
    trailing ``ES`` or ``S`` is stripped before the equality test when the
    remainder is a member."""
    if segment in SECRET_SHAPED_FALSE_POSITIVE_SEGMENTS:
        return True
    return any(
        segment.endswith(plural)
        and segment[: -len(plural)] in SECRET_SHAPED_FALSE_POSITIVE_SEGMENTS
        for plural in ("ES", "S")
    )


def is_secret_shaped_environment_name(name: str) -> bool:
    """Whether *name* is secret-shaped, read case-insensitively.

    An entry of ``SECRET_SHAPED_NAME_SUFFIXES`` matches in two ways. The name
    ends with it, glued or not (``GITHUBTOKEN``, ``MYPASSWORD``,
    ``AWSSECRETACCESSKEY``, ``MONKEY``). Or its own segments, split on ``_``
    and ``-``, appear contiguously and in order with only trailing qualifiers
    after them -- a digit run, a version mark, or a deployment-stage word
    (``PROD``, ``STAGING``, ``DEV``, ``TEST``) -- so a trailing qualifier does
    not hide the word (``ASH_API_KEY_PROD``, ``ASH_DB_PASSWORD_2``,
    ``ASH_TOKEN_STAGING``), while a name whose later segments say something
    else (``ASH_AUTH_ENABLED``, ``ASH_PASS_THRESHOLD``: a flag or a limit
    named after the word, not the word's value) is not matched by this
    reading. A bare name equal to an entry (``PWD``) matches.

    Both readings see each segment with its trailing digits stripped
    (``ASH_API_KEY2``, ``ASH_DB_PASSWORD1``) and with a glued trailing
    qualifier stripped where the remainder is a listed word
    (``ASH_TOKENPROD``).

    The ends-with reading is skipped when the name's last segment equals, as
    written or with a trailing digit run or plural ``ES``/``S`` stripped, one
    of ``SECRET_SHAPED_FALSE_POSITIVE_SEGMENTS`` (``COMPAT``, ``BYPASS``,
    ``COMPASS``, ``OLDPWD``), so those names and their plural or
    digit-qualified spellings (``ASH_BYPASSES``, ``ASH_BYPASS2``) are not
    matched. Those are the only names a plain ends-with test matched and this
    one does not. Equality only: ``BYPASS_TOKEN`` and ``MYCOMPASS_TOKEN`` are
    matched.
    """
    upper = name.upper()
    segments = _name_segments(name)
    canonical = [_canonical_segment(segment) for segment in segments]
    # The name without its trailing qualifier segments, so the ends-with
    # reading sees the word a qualifier followed: ASH_GITHUBTOKEN_2 and
    # ASH_DBPASSWORD_PROD end with a glued word plus a qualifier, which the
    # segment-run reading cannot split and the plain ends-with test did not
    # reach, although ASH_GITHUBTOKEN and ASH_GITHUB_TOKEN_2 both matched.
    kept = len(segments)
    while kept > 1 and _is_trailing_qualifier(segments[kept - 1]):
        kept -= 1
    trimmed = segments[:kept]
    trimmed_canonical = canonical[:kept]
    joined = "_".join(canonical)
    trimmed_joined = "_".join(trimmed)
    trimmed_canonical_joined = "_".join(trimmed_canonical)
    last_is_denylisted = bool(trimmed) and (
        _is_false_positive_segment(trimmed[-1])
        or _is_false_positive_segment(trimmed_canonical[-1])
    )
    if not last_is_denylisted and any(
        upper.endswith(suffix)
        or joined.endswith(suffix)
        or trimmed_joined.endswith(suffix)
        or trimmed_canonical_joined.endswith(suffix)
        for suffix in SECRET_SHAPED_NAME_SUFFIXES
    ):
        return True
    for suffix in SECRET_SHAPED_NAME_SUFFIXES:
        wanted = _name_segments(suffix)
        width = len(wanted)
        if not width:
            continue
        for start in range(len(canonical) - width + 1):
            if canonical[start : start + width] != wanted:
                continue
            if all(
                _is_trailing_qualifier(segment) for segment in segments[start + width :]
            ):
                return True
    return False


def _name_segments(name: str) -> List[str]:
    """*name* upper-cased and split into its non-empty ``_``/``-`` segments."""
    return [segment for segment in re.split(r"[_-]+", name.upper()) if segment]


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
    "mjs",
    "cjs",
    "ts",
    "jsx",
    "tsx",
    # Credential-bearing and configuration files. Left out, the archive
    # converter never extracted such a member and detect-secrets never read it:
    # a private key or a registry token inside an archive went unscanned.
    "pem",
    "key",
    "npmrc",
    "config",
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

#: The command line could not be used, so nothing ran: an unknown command, option
#: or argument, a missing required option, an option value ASH does not accept, or
#: options that cannot be combined. Its own code because click's default for these
#: is 2, which is ASH's code for actionable findings, so a CI gate read a mistyped
#: flag as a scan that found problems. Every command reaches it through this name:
#: click's errors are mapped in cli/main.py, and ASH's own refusals of an invocation
#: exit with it directly.
ASH_EXIT_USAGE_ERROR = 5

#: A scan stopped by Ctrl-C, in any mode: 128 + SIGINT, the shell's convention. Not in
#: ASH_EXIT_CODES below, which lists the outcomes a scan reports; an interrupted scan
#: reports none.
ASH_EXIT_INTERRUPTED = 130

#: A scan stopped by SIGTERM: 128 + SIGTERM, the code the default disposition would
#: have exited with, so a supervisor that sent the signal reads the same verdict it
#: always has -- the difference is that the scan's own stop path ran first
#: (core/cancellation.py, "SIGTERM on the CLI"). Not in ASH_EXIT_CODES, for
#: ASH_EXIT_INTERRUPTED's reason: a terminated scan reports no outcome.
ASH_EXIT_TERMINATED = 143

#: The code one command, `ash dependencies install`, exits with for a --tool it cannot
#: select (a name no plugin has, or a plugin of a type --plugin-type leaves out), and
#: for a --plugin-type that is none of converter, scanner and reporter. The CLI
#: reference documents 2 for them; the command's other usage errors exit
#: ASH_EXIT_USAGE_ERROR. Every place that names this code reads it here, so moving it
#: is a one-line change. ASH_EXIT_CODES below is a scan's own table and does not carry
#: it: the ash://exit-codes resource lists it as that command's own entry
#: (cli/mcp_server.py), in ASH_EXIT_BAD_SELECTION_MEANING's words, which are the CLI
#: reference's for the command's row.
ASH_EXIT_BAD_SELECTION = 2
ASH_EXIT_BAD_SELECTION_MEANING = (
    "a --tool name that matches no plugin, or names a plugin of a type that "
    "--plugin-type leaves out; or a --plugin-type that is none of converter, "
    "scanner and reporter"
)

ASH_EXIT_CODES: Dict[int, str] = {
    0: "success",
    1: "scan errors / scanner failures",
    2: "actionable findings at or above threshold",
    # A config ASH cannot use, or an input it refuses before it scans, such as a
    # linked output directory or a container mount path the runner cannot take.
    3: "invalid config or refused input",
    # 4 is workspace-mode only. It is deliberately NOT an overload of 2: a
    # workspace definition error means nothing was scanned, whereas 2 means a
    # scan completed and found something. See models/workspace.py for why the
    # RFC's original assignment of 2 was not used.
    4: "workspace definition or policy error",
    ASH_EXIT_USAGE_ERROR: "usage error",
}


#: The ASH_OFFLINE values that name offline mode, and the ones that name online
#: mode. They are pairs (ON/OFF, Y/N, YES/NO, TRUE/FALSE, 1/0): a value that names
#: one side of a pair names the other side's opposite too, so the words an operator
#: reaches for to turn offline mode on work as the words for turning it off do.
#: Anything else is unrecognized, and is said so once.
_OFFLINE_OFFLINE_VALUES = ("YES", "TRUE", "1", "ON", "Y")
_ONLINE_OFFLINE_VALUES = ("", "NO", "FALSE", "0", "OFF", "N")


def is_offline_mode() -> bool:
    """Check if ASH is running in offline mode via ASH_OFFLINE env var.

    YES, TRUE, 1, ON or Y, whatever the case and with the blanks around the value
    removed (``set ASH_OFFLINE=YES `` in a Windows ``cmd`` keeps the trailing
    blank, and the container init script strips before it compares). NO, FALSE, 0,
    OFF, N and an empty value leave ASH online. Any other value leaves ASH online
    too, and one warning says so. ``ON`` and ``Y`` used to be in that last group,
    though their opposites ``OFF`` and ``N`` were accepted: an air-gapped run
    that set ``ASH_OFFLINE=on`` went online with a warning.
    """
    raw = os.environ.get("ASH_OFFLINE")
    value = str(raw if raw is not None else "NO").strip().upper()
    if value in _OFFLINE_OFFLINE_VALUES:
        return True
    if value not in _ONLINE_OFFLINE_VALUES:
        warn_relative_value_once(
            "ASH_OFFLINE",
            str(raw),
            f"ASH_OFFLINE={raw!r} is not recognized, so ASH runs online. Set it to "
            "YES, TRUE, ON, Y or 1 for offline mode.",
        )
    return False
