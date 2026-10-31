# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import contextvars
import functools
import json
import logging
import os
import platform
import posixpath
import re
import shlex
import shutil
from subprocess import (
    CalledProcessError,
    CompletedProcess,
    SubprocessError,
)  # nosec B404 - Using the exception classes to evaluate subprocess invocations
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    IO,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Sequence,
    Set,
    Tuple,
)
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname
import typer
import threading
import io
from importlib_metadata import import_module

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

# Import subprocess utilities
from automated_security_helper.core.constants import (
    ASH_ASSETS_DIR,
    ASH_REPO_LATEST_REVISION,
    is_readable_environment_name,
    is_secret_shaped_environment_name,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
)
from automated_security_helper.core.cancellation import (
    CancelEvent,
    ScanCancelled,
    current_cancel_event,
    raise_if_cancelled,
    record_tool_pid,
)
from automated_security_helper.interactions.container_leftovers import (
    discard_record,
    leftover_records,
    new_container_name,
    record_container,
    record_env_dir,
    remove_leftovers,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.console import (
    COMMAND_READING_RUNNERS,
    CommandSafeStream,
    echo,
    secho,
)
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    could_not_stop_sentence,
    create_completed_process,
    in_tree_tools_allowed,
    raise_called_process_error,
)
from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.log import ASH_LOGGER, SHOW_LOCALS_VARIABLE
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.threads import ash_thread
from automated_security_helper.utils.terminal_text import shown_on_one_line
from automated_security_helper.utils.version_management import _load_toml

# Pattern for safe git revision values: alphanumeric, dots, hyphens, underscores, forward slashes
_SAFE_REVISION_PATTERN = re.compile(r"^[A-Za-z0-9._\-/]+$")
#: A UID or GID as the build and the runner read one.
_ASCII_DIGITS = re.compile(r"[0-9]+")

# The characters ./ash and Invoke-ASH hold an image name to. ASCII only and matched
# whole (fullmatch), so the Kelvin sign is not K and a trailing newline is not the end
# of the name. A name may not start with '-' either; that is checked beside it.
_IMAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9._:/@-]+", re.ASCII)

# The code ./ash and Invoke-ASH refuse their own input with, and ASH's code for input
# it refuses (ASH_EXIT_CODES[3]).
_WRAPPER_REFUSAL_EXIT = 3


# Discovery order for OCI runners (first found wins)
_OCI_RUNNER_CANDIDATES = ["finch", "docker", "nerdctl", "podman"]

#: The runner markers that go on the runner's command line with their values when
#: OCI_RUNNER_WRAPPER is set. Spelled out rather than taken from
#: COMMAND_READING_RUNNERS, so a name added there later goes by name, and its value
#: never reaches the command line.
RUNNER_MARKERS_ON_ARGV = ("GITHUB_ACTIONS", "TF_BUILD", "TEAMCITY_VERSION")


class RunnerMarkerRefused(ValueError):
    """A runner marker whose value cannot go on the runner's command line."""


def _runner_marker_args(
    oci_command_prefix: List[str], environ: Mapping[str, str]
) -> List[str]:
    """The ``-e`` arguments that give the container each runner marker that is set.

    Under a runner that reads workflow commands from the job's output, the scan
    inside checks a terminal's lines too, but only when it sees the runner's
    variable. Without a wrapper each goes by name (as ./ash does), so the container
    gets the job's own value. A wrapper need not pass this process's environment on
    (sudo's default env_reset does not), so through one each name in
    RUNNER_MARKERS_ON_ARGV goes with its value, as one argument: they are public
    markers of the CI system, not secrets. A value holding a newline or a NUL is
    refused rather than put there, and the refusal names the variable, not its value.
    """
    args: List[str] = []
    for name in COMMAND_READING_RUNNERS:
        value = environ.get(name)
        if not value:
            continue
        if not oci_command_prefix or name not in RUNNER_MARKERS_ON_ARGV:
            args.extend(["-e", name])
            continue
        if "\n" in value or "\0" in value:
            raise RunnerMarkerRefused(
                f"{name} holds a newline or NUL character, so it is not passed to the "
                "container: with OCI_RUNNER_WRAPPER set, GITHUB_ACTIONS, TF_BUILD and "
                "TEAMCITY_VERSION go on the runner's command line with their values. "
                f"Remove the character from {name}, or unset OCI_RUNNER_WRAPPER so the "
                "container gets the variable by name."
            )
        args.extend(["-e", f"{name}={value}"])
    return args


# Memoizes the buildx capability probe, keyed by resolved runner path.
_BUILDX_SUPPORT_CACHE: dict[str, bool] = {}


def _validate_ash_revision(revision: str) -> bool:
    """Validate that an ASH revision string is safe for use as a Docker build-arg.

    Rejects values containing shell metacharacters that could enable
    command injection in build-arg contexts.

    Args:
        revision: The revision string to validate.

    Returns:
        True if the revision is safe, False otherwise.
    """
    if not revision:
        return False
    # fullmatch: with match, `$` also matches before a final newline, which let a
    # revision with one through to the build argument.
    return _SAFE_REVISION_PATTERN.fullmatch(revision) is not None


# ---------------------------------------------------------------------------
# Refusals: results that never reached a container
# ---------------------------------------------------------------------------

#: Set on a result run_ash_container returns before any container ran.
_NOT_STARTED_ATTR = "ash_container_not_started"

#: Set on a failed result whose container may still be running, so the record of
#: the container is kept for the next sweep (_execute_container).
_MAY_STILL_RUN_ATTR = "ash_container_may_still_run"


def _not_started(result):
    """Mark ``result`` as a refusal: run_ash_container stopped before the run phase.

    The refusals (no runner, a non-numeric UID or GID, a runner marker the wrapper's
    command line cannot take, an unsafe revision, a missing Dockerfile, a failed build,
    an unusable source or output directory) come back as a
    non-zero ``CompletedProcess`` or ``CalledProcessError``, exactly like a container
    that ran and exited 1. A status of 1 is also a verdict the in-container CLI reaches
    from a results file, so on the status alone the caller cannot tell "the scan found
    problems" from "no scan was attempted", and went on to look for a results file that
    nothing could have written. The mark is what separates them. It is set on the object
    rather than carried by a subclass so that a build's ``CalledProcessError`` reaches the
    caller unchanged, with its own returncode and output.
    """
    setattr(result, _NOT_STARTED_ATTR, True)
    return result


def container_was_started(result) -> bool:
    """Whether ``result`` came from a container run rather than a refusal before one.

    Compared with ``is True`` so that only the mark set by :func:`_not_started` counts:
    a stand-in result whose attributes all exist (a ``MagicMock``) still reads as a run.
    """
    return getattr(result, _NOT_STARTED_ATTR, False) is not True


#: The paths beside the package that mark a full clone of the ASH repository.
_CHECKOUT_MARKERS = (
    ".github",
    ".gitignore",
    ".dockerignore",
    "Dockerfile",
    "pyproject.toml",
    "NOTICE",
    "docs",
    "tests",
)


def _checkout_root() -> Path:
    """The directory a full clone would put this package in, whether or not it is one.

    From the module's real path: a repository on sys.path holding a symlink named
    automated_security_helper is not a clone of ASH, wherever the link points.
    """
    return Path(__file__).resolve().parent.parent.parent


#: Directory names an installer puts packages in; a clone is never one of them.
_INSTALL_DIR_NAMES = ("site-packages", "dist-packages")


def _is_checkout(root: Path) -> bool:
    """Whether *root*, the directory holding the package, is a clone of the repository.

    The markers alone are not enough, since the same files can sit beside an
    installed package, for example in a project's own ``.venv/.../site-packages``.
    A package an installer put in place sits in a site-packages (or dist-packages)
    directory with its distribution's dist-info beside it, and a clone has neither,
    so either one rules a clone out.
    """
    if root.name in _INSTALL_DIR_NAMES:
        return False
    if any(root.glob("automated_security_helper-*.dist-info")):
        return False
    return all(root.joinpath(marker).exists() for marker in _CHECKOUT_MARKERS)


def _direct_url_json_path() -> Path | None:
    """Where the installer recorded the source of this package (PEP 610), if anywhere.

    The direct_url.json of the package's own dist-info (_own_dist_info), not the
    first distribution of the name on sys.path, and not one named from
    ``__version__``, which comes from that same sys.path lookup. None for a
    checkout or an editable install, which have no dist-info beside the package.
    """
    own_dist_info = _own_dist_info()
    return own_dist_info.joinpath("direct_url.json") if own_dist_info else None


def get_ash_revision(quiet: bool = False) -> str | None:
    """
    Get the revision of the Automated Security Helper repo to install based on how the
    current version of the package was installed.

    - If ASH is installed in editable mode or is within a full clone of the
    repository, return 'LOCAL'
    - If ASH was installed via `pip install` where only the package info and some of
    the source is available, then attempt to resolve the installed source and provide the
    target Git revision to install ASH within the container image.

    Args:
        quiet: Resolve the revision without logging how, for a message that names
            it after the build has already logged it.

    Returns:
        str: The revision of the Automated Security Helper container
    """

    def info(message: str) -> None:
        if not quiet:
            ASH_LOGGER.info(message)

    def warning(message: str) -> None:
        if not quiet:
            ASH_LOGGER.warning(message)

    return_val = None
    if _is_checkout(_checkout_root()):
        info(
            "ASH installation appears to be alongside the repository contents, building with LOCAL source"
        )
        return "LOCAL"

    direct_url_json_path = _direct_url_json_path()
    if direct_url_json_path is not None and _is_file(direct_url_json_path):
        if not quiet:
            echo(
                f"Found direct_url.json file for module @ {direct_url_json_path.as_posix()}"
            )
        try:
            # Read as UTF-8, as _recorded_direct_url reads the same file: the two
            # LOCAL decisions then read the same bytes the same way.
            direct_url_json = json.loads(
                direct_url_json_path.read_text(encoding="utf-8")
            )
            if isinstance(direct_url_json, dict) and "url" in direct_url_json:
                url = direct_url_json["url"]
                if not isinstance(url, str):
                    # Caught below: a record of the wrong shape falls back to the
                    # recorded revision, as an unreadable one does.
                    raise TypeError("the url in direct_url.json is not a string")
                if url.startswith("file://") and _source_tree_in(direct_url_json):
                    info(
                        "ASH installed from local file path, building with LOCAL source"
                    )
                    return "LOCAL"
                elif url.startswith("file://"):
                    # A wheel or an sdist file, or a directory that is gone or holds
                    # no ASH source tree now (`pip install <dir>`, then the directory
                    # deleted or replaced). There is nothing to build from that
                    # path, and the record carries no revision, so what the package
                    # build recorded follows below. Never LOCAL: a LOCAL build with
                    # no ASH tree would have nothing to build but the working
                    # directory, the repository being scanned.
                    info(
                        "ASH was installed from a local path that holds no ASH source "
                        "tree, so the image installs the revision its package build "
                        "recorded"
                    )
                    return_val = ASH_REPO_LATEST_REVISION
                elif "vcs_info" in direct_url_json and isinstance(
                    direct_url_json["vcs_info"], dict
                ):
                    vcs_info = direct_url_json["vcs_info"]
                    revision = (
                        vcs_info.get("requested_revision")
                        or vcs_info.get("commit_id")
                        or ASH_REPO_LATEST_REVISION
                    )
                    if not isinstance(revision, str):
                        raise TypeError(
                            "the vcs_info revision in direct_url.json is not a string"
                        )
                    return_val = revision
                    info(
                        f"Resolved source revision for ASH to use during container image build: {return_val}"
                    )
                else:
                    warning(
                        "direct_url.json exists but lacks vcs_info, falling back to latest revision"
                    )
                    return_val = ASH_REPO_LATEST_REVISION
        # OSError: a record that cannot be read. ValueError covers JSONDecodeError and
        # a record that is not UTF-8.
        except (OSError, ValueError, KeyError, TypeError) as e:
            warning(
                f"Failed to read direct_url.json: {e}, falling back to latest revision"
            )
            return_val = ASH_REPO_LATEST_REVISION
    else:
        return_val = ASH_REPO_LATEST_REVISION

    # With no git source in direct_url.json, ASH_REPO_LATEST_REVISION is what the
    # package build recorded: the commit it was built from, or a placeholder when it
    # could not tell. A record of the wrong shape leaves nothing at all.
    if return_val is None or not _names_a_ref(return_val):
        return _release_revision()
    if return_val == ASH_REPO_LATEST_REVISION and not _COMMIT_ID_PATTERN.fullmatch(
        return_val
    ):
        # A package built before the build hook recorded commit ids records the
        # branch it was built on; the image gets that branch's tip, whatever has
        # landed on it since. Through the local helper, so a quiet resolve (the
        # read-back error that names the revision after the build logged it) does
        # not log it a second time.
        warning(
            f"This installation of ASH recorded the branch {return_val!r} it was built "
            f"on, not a commit, so the image installs that branch's current tip. Pass "
            f"--ash-revision-to-install to choose the revision."
        )
    return return_val


def _own_dist_info() -> Path | None:
    """The dist-info of the running package: the one installed beside it.

    Not importlib.metadata.distribution(), which returns the first distribution of
    the name on sys.path. With the working directory on sys.path (``python -m``,
    ``python -c``, ``PYTHONPATH=.``) that can be a dist-info directory the scanned
    repository commits, which would then choose what the image build installs.
    The installer writes the running package's own record next to it, and there is
    exactly one for an installed package; an editable install or a checkout has
    none there.
    """
    try:
        # Its real path: a dist-info planted beside a symlinked package, in a
        # repository on sys.path, is not this package's record.
        package_dir = Path(
            import_module("automated_security_helper").__path__[0]
        ).resolve()
    except (AttributeError, IndexError, TypeError, OSError):
        return None
    candidates = [
        path
        for path in package_dir.parent.glob("automated_security_helper-*.dist-info")
        if path.is_dir()
    ]
    return candidates[0] if len(candidates) == 1 else None


def _installed_version() -> str | None:
    """The version in the name of the running package's own dist-info, if any."""
    own_dist_info = _own_dist_info()
    if own_dist_info is None:
        return None
    return own_dist_info.name[len("automated_security_helper-") : -len(".dist-info")]


#: What hatch_build.py writes to assets/ASH_INSTALLED_REVISION when it cannot name
#: the commit (no git, a source tree without .git, an error), and what a missing
#: asset reads as (core/constants.py). "HEAD" is what builds before commit ids
#: recorded for a detached checkout, a tag's included; ci/stage_build_assets.py
#: writes "ERROR: ...". None of them is a ref the image build can clone.
_UNRECORDED_REVISIONS = frozenset(
    {"", "HEAD", "unknown-commit", "no-git-available", "build-error"}
)


def _names_a_ref(revision: str) -> bool:
    """False for the placeholders above, which name no branch, tag or commit."""
    revision = revision.strip()
    return revision not in _UNRECORDED_REVISIONS and not revision.startswith("ERROR")


def _release_revision() -> str | None:
    """A guess at the revision: the release tag of the installed version, or None.

    The last fallback, when neither direct_url.json nor the package build names a
    revision: a package built where git could not name the commit (a source
    tarball, such as the one CI renders the Homebrew formula from) records
    "unknown-commit", which `git clone --branch` in the image build cannot clone.

    It is a guess, and logged as one. Every ASH release is tagged ``v<version>``
    (v3.7.0), but the version in pyproject.toml changes only at a release, so an
    unreleased commit carries the version of the release before it and this would
    install that release instead. A development, pre-, post- or local version has
    no tag at all; None then, and run_ash_container refuses the build and names
    --ash-revision-to-install.

    The version is read from the running package's own dist-info, never from
    importlib.metadata, for the reason _own_dist_info gives.
    """
    version = _installed_version()
    try:
        parsed = Version(str(version))
    except InvalidVersion:
        return None
    if parsed.is_prerelease or parsed.is_postrelease or parsed.local is not None:
        return None
    tag = f"v{parsed}"
    ASH_LOGGER.warning(
        f"This installation of ASH recorded no source revision, so the image installs "
        f"{tag}, the release tag of its version {version}. That is a guess: a build "
        f"of an unreleased commit carries the version of the release before it. Pass "
        f"--ash-revision-to-install to choose the revision."
    )
    return tag


def _unresolved_revision_message() -> str:
    """Why a build has no revision to install, and what to pass instead."""
    version = _installed_version() or "unknown"
    return (
        f"Cannot tell which ASH revision to build into the image: this installation "
        f"of ASH (version {version}) records no source revision, and that version is "
        f"not a release, so it has no tag to build. Pass --ash-revision-to-install "
        f"with a tag, a branch or a full commit id of the ASH repository."
    )


#: A full commit id, which `git clone --branch` cannot take. The Dockerfile clones the
#: repository's branches and tags and builds the id only if one of them reaches it.
_COMMIT_ID_PATTERN = re.compile(r"^[0-9a-f]{40}$")

#: The shape of ASH's release tags (v3.7.0, v3.0.0-beta), which are never moved. The
#: floating major-version tag (v3) is not in it: it moves with every release.
_RELEASE_TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+(?:[-.][0-9A-Za-z][0-9A-Za-z.-]*)?$")

#: The Dockerfile ARG declared directly above the clone step of its uv-reqs stage.
CLONE_DATE_BUILD_ARG = "ASH_CLONE_DATE_EPOCH"


def _revision_moves(revision: str | None) -> bool:
    """Whether the image build of ``revision`` clones something that can change.

    True for a branch. Decided from the name alone, without asking the remote: a
    full commit id and a tag shaped like ASH's releases always clone the same
    tree, LOCAL clones nothing, and any other name is taken for a branch. A tag of
    some other shape is taken for one too, which costs that build a fresh clone
    and nothing else. The other mistake, a branch taken for a tag, would serve the
    branch's first clone from the build cache to every later build.
    """
    if revision is None or revision == "LOCAL":
        return False
    return not (
        _COMMIT_ID_PATTERN.fullmatch(revision)
        or _RELEASE_TAG_PATTERN.fullmatch(revision)
    )


def validate_path(path: str | Path) -> Path:
    """
    Validate that a path is safe and convert it to a Path object.

    Args:
        path: The path string to validate

    Returns:
        Path: The validated Path object

    Raises:
        ValueError: If the path is not safe
    """
    # Convert to absolute path
    abs_path = Path(path).resolve()

    # Check if the path exists. A path that cannot be looked at (an unsearchable
    # parent) is refused the same way, not raised past the caller's ValueError
    # handling as a traceback.
    try:
        exists = abs_path.exists()
    except OSError as e:
        raise ValueError(f"Path cannot be checked: {abs_path} ({e.strerror or e})")
    if not exists:
        raise ValueError(f"Path does not exist: {abs_path}")

    return abs_path


# The runtime hands the interrupt to the container, whose ASH stops as an
# interrupted local scan does. This was SIGTERM, which killed the runtime before it
# could pass anything on. Shared with Nix mode, which runs its shell the same way.
_stop_after_interrupt = subprocess_utils.stop_after_interrupt

#: Set on the OSError that ``run_cmd_direct`` raises when the runtime could not be
#: started, to tell it from an OSError raised once the runtime was running.
RUNTIME_NOT_STARTED_ATTRIBUTE = "ash_runtime_not_started"


def _stop_the_runtime(process, **kwargs) -> bool:
    """:func:`_stop_after_interrupt`, with a kill if it is itself cut short.

    The helper handles a second Ctrl-C while it waits out the grace (a
    KeyboardInterrupt) and kills the runtime then. A second SIGTERM, the order a
    CI job's cancel sends after a first one, reaches this process as a SystemExit
    raised by the run step (``_termination_raises``), which the helper does not
    handle: it unwound out of the wait with the runtime still running after ASH
    had exited. Anything that ends the helper early is followed by a kill before
    it goes on.
    """
    try:
        return _stop_after_interrupt(process, **kwargs)
    except BaseException:
        try:
            process.kill()
        except OSError:
            pass  # it has already exited, or the kernel refuses the signal
        raise


def _shown_command_text(cmd_list: Sequence[object]) -> str:
    """A command's argv as it may be printed.

    Each --config-overrides value is shown as its key, and the run's
    environment values (the spawn's carrier) are hidden, the same treatment
    the debug command echo applies: a --build-arg or -e pair can hold a
    value a config read from the environment.
    """
    from automated_security_helper.utils.error_text import text_without_values

    args = [str(item) for item in cmd_list if item is not None]
    shown = " ".join(shlex.quote(arg) for arg in subprocess_utils.shown_arguments(args))
    return text_without_values(shown, subprocess_utils._SPAWN_VALUES.get())


def _shown_build_failure(e: BaseException, values: Tuple[str, ...]) -> str:
    """A failed build's error text as it may be printed.

    A CalledProcessError's own text quotes its full argv, so the command is
    rebuilt through the same treatment the debug command echo applies; any
    other error's text is passed through the value hiding only. ``values``
    are the carried environment values, passed explicitly because the
    handler that prints this runs outside the build's spawn context. The
    build's own output is not part of this text: it streams to the terminal
    as the build runs.
    """
    from automated_security_helper.utils.error_text import text_without_values

    if isinstance(e, CalledProcessError):
        joined = " ".join(
            shlex.quote(arg)
            for arg in subprocess_utils.shown_arguments(
                [str(item) for item in (e.cmd or []) if item is not None]
            )
        )
        text = f"Command {joined!r} returned non-zero exit status {e.returncode}."
    else:
        text = str(e)
    return text_without_values(text, values)


def _carried_values_by_band(
    environment_names: Sequence[str],
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """The chain's carried values split for the stream: ``(all, strict)``.

    ``all`` is every present value, the spawn's carrier as before. ``strict``
    is the subset read from secret-shaped names
    (:func:`is_secret_shaped_environment_name`): the streamed report hides
    those whatever their length, as a whole word or a quoted echo, so a short
    secret never rides the bare-word exemption a severity or a region gets.
    """
    all_values = []
    strict = []
    for name in environment_names:
        value = os.environ.get(name, "")
        if not value:
            continue
        all_values.append(value)
        if is_secret_shaped_environment_name(name):
            strict.append(value)
    return tuple(all_values), tuple(strict)


def _streamed_line(
    line: str,
    hidden_values: Tuple[str, ...],
    strict_values: Tuple[str, ...] = (),
    *,
    scan_report: bool = False,
) -> str:
    """One line of the child's streamed output with the run's carried values
    hidden.

    The child's own messages already redact what its rules say, and its
    output is the operator's scan report, so the host's pass here is only for
    a carried value quoted back whole: a value long enough to be matched
    anywhere is hidden wherever it appears, a short one only where the line
    quotes it. A bare common word that happens to equal a short carried value
    (a severity, a region) prints as the child wrote it. Two bounds on that
    exemption: ``strict_values`` (the values of secret-shaped names) are
    matched in the default band whatever the stream is, so a short one is
    hidden as a whole word and as a quoted echo, where the loosened band
    would let it print bare; and a stream that is not the scan's report
    (``scan_report=False``, the default, which is also the carrier's default:
    the image build, and the runtime's own stderr) keeps that default band for
    every value, because the exemption's reason -- the report's own words --
    does not apply there.

    The stream is read a line at a time, so a value that holds a line break is
    matched by each of its lines: the whole value never appears in one line, and
    a child that quotes it back prints it one line at a time."""
    from automated_security_helper.utils.error_text import text_without_values
    from automated_security_helper.utils.numeric_text import MIN_ANYWHERE_LENGTH

    hidden_values = _value_lines(hidden_values)
    strict_values = _value_lines(strict_values)
    if not scan_report:
        return text_without_values(line, tuple(hidden_values) + tuple(strict_values))
    out = line
    if strict_values:
        out = text_without_values(out, strict_values)
    return text_without_values(out, hidden_values, min_length=MIN_ANYWHERE_LENGTH)


#: A line of a multi-line value that is the value's shape and carries none of it: a
#: PEM armor or separator line, a line of punctuation alone, or a short JSON
#: ``"key": scalar`` pair. Hidden on its own, one of these would be hidden
#: wherever the report quotes the same words (the private-key header a finding
#: describes, a JSON ``"type": "service_account"`` in an example).
_STRUCTURE_LINE = re.compile(
    r"""^(?:
        -{3,}[^\n]*  # PEM armor, a rule line
      | [\W_]+  # punctuation alone
      | "[^"\n]{1,30}"\s*:\s*(?:"[^"\n]{0,24}"|true|false|null|-?\d{1,6})\s*,?
    )$""",
    re.VERBOSE,
)


def _value_lines(values: Tuple[str, ...]) -> Tuple[str, ...]:
    """``values`` with each one that holds a line break followed by its lines.

    Each line is stripped, and only a line long enough to be matched as a value
    of its own (``MIN_REDACTED_LENGTH``) is added: a brace or a blank line of a
    multi-line value would otherwise hide every brace of the output. A line that
    is only the value's shape (``_STRUCTURE_LINE``) is left out for the same
    reason. Nothing is added twice, so the answer can be passed through again
    unchanged.
    """
    from automated_security_helper.utils.numeric_text import MIN_REDACTED_LENGTH

    out: List[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
        if "\n" in value or "\r" in value:
            for part in value.splitlines():
                part = part.strip()
                if _STRUCTURE_LINE.fullmatch(part):
                    continue
                if len(part) >= MIN_REDACTED_LENGTH and part not in seen:
                    seen.add(part)
                    out.append(part)
    return tuple(out)


def run_cmd_direct(
    cmd_list: Sequence[object],
    check: bool = True,
    debug: bool = False,
    shell: bool = False,
    env: Mapping[str, str] | None = None,
) -> CompletedProcess[str]:
    """
    Run a command and stream output directly to console without Rich panels.

    The wait reads the scan's cancel event (core/cancellation.py): when it is
    set while the command runs, the child is stopped through the interrupt stop
    path and :class:`ScanCancelled` is raised. Without that read, a SIGTERM to
    ASH set the event and nothing looked at it, so the scan ran to completion
    as though no signal had arrived.

    Whether the streamed copy keeps the scan report's loosened band rides the
    spawn's carrier (``_SPAWN_SCAN_REPORT``, set by ``_spawn_values``): only
    the scan's own run is marked, so the image build's stream keeps the strict
    band. Only stdout is the report; the runtime's stderr always keeps the
    strict band.

    Args:
        cmd_list: List of command arguments; None entries are dropped and the
            rest made strings
        check: Whether to check the return code
        debug: Whether to print debug information
        env: The command's environment, or None for this process's

    Returns:
        subprocess.CompletedProcess: The result of the command
    """
    # Filter out empty or None values
    args = [str(item) for item in cmd_list if item is not None]

    # Log the command for debugging, each --config-overrides value as its key,
    # and the run's environment values hidden (the spawn's carrier): a mount
    # source or -e pair can hold a value a config read from the environment.
    if debug:
        from automated_security_helper.utils.error_text import text_without_values

        shown = " ".join(
            shlex.quote(arg) for arg in subprocess_utils.shown_arguments(args)
        )
        shown = text_without_values(shown, subprocess_utils._SPAWN_VALUES.get())
        echo(f"Running command: {shown}")

    # Create buffers for stdout and stderr
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()

    # The child can quote a carried value back in its output (it received it
    # in its arguments or environment), so the streamed copy hides the
    # spawn's carried values line by line. Read here, before the reader
    # threads start, so the threads see the caller's carrier whatever their
    # own context holds; the buffered copy keeps the bytes, and the failure
    # handler hides the values again at its own print.
    hidden_values = subprocess_utils._SPAWN_VALUES.get()
    strict_values = subprocess_utils._SPAWN_STRICT_VALUES.get()
    scan_report_stream = subprocess_utils._SPAWN_SCAN_REPORT.get()

    # Function to read from a pipe and stream output
    def read_pipe(pipe: IO[str], is_stderr: bool = False) -> None:
        buffer = stderr_buffer if is_stderr else stdout_buffer
        # The containerized ASH's output is already rendered, and shows the
        # controls its own messages quote; on a terminal it carries the colors -t
        # gave it. So it is written through the console stream's line check, not
        # the text rule: no line of it is a CI command, and its colors and
        # progress redraws survive except where a code would conceal a
        # configured value, which text_without_values then strips.
        stream = CommandSafeStream(
            (lambda: sys.stderr) if is_stderr else (lambda: sys.stdout)
        )
        # The pipe is drained to its end whatever the console does with the
        # copy: a reader that stopped at the first failed console write (a
        # closed stdout, a terminal gone) left the child blocked on a full
        # pipe, and the wait below then never ended. The failure is reported
        # once; later lines are kept in the buffer and not shown.
        console_failed = False
        try:
            for line in iter(pipe.readline, ""):
                buffer.write(line)
                if console_failed:
                    continue
                try:
                    stream.write(
                        _streamed_line(
                            line,
                            hidden_values,
                            strict_values,
                            # The runtime's own stderr is never the scan's report:
                            # a mount failure can quote an environment value as a
                            # path segment, so it keeps the strict band.
                            scan_report=scan_report_stream and not is_stderr,
                        )
                    )
                except Exception as e:
                    console_failed = True
                    echo(
                        f"Error writing {'stderr' if is_stderr else 'stdout'} to the "
                        f"console: {str(e)}",
                        err=True,
                    )
        except Exception as e:
            error_msg = f"Error reading {'stderr' if is_stderr else 'stdout'}: {str(e)}"
            echo(error_msg, err=True)

    # The threads that read stdout and stderr, daemon threads so they don't block
    # program exit
    readers: List[threading.Thread] = []

    # A scan already cancelled starts no runtime. A SIGTERM that landed
    # between the image build returning and this point set the event with
    # nothing yet reading it, and the poll loop below only looks after the
    # spawn, so without this check the runtime started mid-cancel and
    # outlived the exit. Checked before the held window, as the spawn paths
    # in utils/subprocess_utils.py check theirs: a Ctrl-C arriving here is an
    # ordinary unheld interrupt that starts nothing, where a check inside the
    # window held it, started the runtime, and only then stopped it.
    raise_if_cancelled()

    # A Ctrl-C while the runtime is being started is held until the process is in
    # hand, and released inside the block below (subprocess_utils.HeldInterrupt).
    with subprocess_utils.HeldInterrupt() as held:
        # Create process using subprocess_utils
        try:
            process = subprocess_utils.create_process_with_pipes(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
                args=args,
                env=dict(env) if env is not None else None,
                text=True,
                shell=shell,
            )
        except OSError as error:
            # The only OSError that means no runtime exists: any raised later
            # is from a runtime that was running (_execute_container).
            setattr(error, RUNTIME_NOT_STARTED_ATTRIBUTE, True)
            raise
        # Line endings untranslated: in universal-newline mode a carriage
        # return ends a line and is read back as a line feed, so every
        # progress redraw the runtime printed became a line of its own on the
        # console and in the captured copy. Each line is still read one at a
        # time, so the console rewrites in place as the runtime meant.
        for pipe in (process.stdout, process.stderr):
            reconfigure = getattr(pipe, "reconfigure", None)
            if reconfigure is not None:
                try:
                    reconfigure(newline="")
                except (OSError, ValueError, TypeError):
                    pass
        # The runtime shares this process's group, so the die-now branches'
        # group kill cannot name it: recorded by pid and forgotten the
        # moment its exit is observed, before the reap.
        record_tool_pid(process.pid)

        # The runtime is running from here on, so a Ctrl-C at any point stops it as
        # one during the wait does: the readers are made and started inside this
        # block. One that came while they were being made or started went past the
        # handler: ASH exited 130 at once, and the runtime, given neither its grace
        # nor a kill, ran on after it.
        try:
            held.release()
            for pipe, is_stderr in ((process.stdout, False), (process.stderr, True)):
                # In this context, copied, so what the readers echo is checked
                # and attributed as this run's (utils/threads.py).
                reader = ash_thread(read_pipe, args=(pipe, is_stderr), daemon=True)
                readers.append(reader)
                reader.start()
            cancel_event = current_cancel_event()
            while True:
                # Observe the exit and drop the die-now record before poll()
                # reaps: a record outliving the reap aims a later SIGINT at
                # whatever process holds the pid next.
                subprocess_utils.discard_tool_pid_once_exited(process)
                if process.poll() is not None:
                    break
                if cancel_event is not None and cancel_event.is_set():
                    # The scan was cancelled: the CLI's SIGTERM handler does
                    # nothing but set the event, so this wait is where the stop
                    # happens, through the same path as the Ctrl-C arm below.
                    # The signal was delivered to this process alone, so the
                    # runtime has not been interrupted yet, whatever the
                    # terminal probe would say.
                    stopped = _stop_the_runtime(process, child_got_the_interrupt=False)
                    for reader in readers:
                        # A thread that was never started cannot be joined.
                        if reader.ident is not None:
                            reader.join(timeout=5.0)
                    if stopped:
                        raise ScanCancelled(
                            "the scan was cancelled while the container runtime ran"
                        )
                    # The grace ran out and the kernel refused the kill, so the
                    # runtime may still run. The cancel says so and carries the
                    # pid as data, as the spawn layer's cancels do, and the
                    # event records it for the exit line, which names survivors
                    # from the records, never from the text.
                    if isinstance(cancel_event, CancelEvent):
                        cancel_event.note_could_not_stop(
                            "container runtime", process.pid
                        )
                    raise ScanCancelled(
                        "the scan was cancelled while the container runtime ran; "
                        + could_not_stop_sentence(
                            f"the container runtime (pid {process.pid})"
                        ),
                        could_not_stop=(("container runtime", process.pid),),
                    )
                time.sleep(0.1)
        except KeyboardInterrupt:
            _stop_the_runtime(process)
            for reader in readers:
                # A thread that was never started cannot be joined.
                if reader.ident is not None:
                    reader.join(timeout=5.0)
            # The caller reports the interrupt and exits 130, as an interrupted local
            # scan does. Returning the runtime's status instead made a Ctrl-C read as
            # the container's own failure: -15, which sys.exit turned into 241.
            raise
        except SystemExit:
            # A SIGTERM relayed as an exit by the run step's _termination_raises:
            # the signal was delivered to this process alone, so the runtime has
            # received nothing. Without this arm the exit unwound past the wait
            # with the runtime left running.
            stopped = _stop_the_runtime(process, child_got_the_interrupt=False)
            if not stopped:
                # The kill was refused, so the runtime may outlive the exit
                # after all: recorded on the scan's event, when there is one,
                # for the exit line. The exit itself is re-raised unchanged.
                event = current_cancel_event()
                if isinstance(event, CancelEvent):
                    event.note_could_not_stop("container runtime", process.pid)
            for reader in readers:
                if reader.ident is not None:
                    reader.join(timeout=5.0)
            raise
        finally:
            # The stop paths and the loop above discard the record themselves;
            # this net catches an exit that landed between an observation and
            # its reap. A child still running keeps its record: it is exactly
            # the one a die-now signal must still be able to kill.
            subprocess_utils.discard_tool_pid_once_exited(process)

    # Join threads before reading buffers to avoid race condition. The join is
    # bounded: a pipe a grandchild still holds open never closes. A reader still
    # running then is said once, so a captured copy read without its tail is
    # not taken for the whole output.
    for reader in readers:
        reader.join(timeout=5.0)
    if any(reader.is_alive() for reader in readers):
        ASH_LOGGER.warning(
            "The container runtime exited but its output was still being read "
            "after 5 seconds (a process it started may hold the pipe open); "
            "the captured copy of its output may be incomplete."
        )

    # Get the captured output (safe now that threads are joined)
    stdout = stdout_buffer.getvalue()
    stderr = stderr_buffer.getvalue()

    # Create a CompletedProcess object
    result = create_completed_process(
        args=args,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
    )

    # Check return code if requested
    if check and result.returncode != 0:
        raise_called_process_error(
            returncode=result.returncode,
            cmd=args,
            output=stdout,
            stderr=stderr,
        )

    return result


# ---------------------------------------------------------------------------
# Private helpers extracted from run_ash_container
# ---------------------------------------------------------------------------


def _find_runner(name: str) -> str | None:
    """Thin wrapper around find_executable used to enable test monkeypatching."""
    try:
        return subprocess_utils.find_executable(name)
    except Exception:
        ASH_LOGGER.debug(f"Unable to find {name} -- continuing")
        return None


def _resolve_oci_runner(oci_runner: str | None, quiet: bool = False) -> str:
    """Discover and return the path to an OCI runner.

    Args:
        oci_runner: Explicit runner name to use, or None to auto-discover.
        quiet: Log the resolved path at debug instead of info. A step that looks
            for a runtime ahead of the run's own resolution passes it, so the
            line is not printed twice.

    Returns:
        The resolved path to the OCI runner binary.

    Raises:
        RuntimeError: When no runner is found.
    """
    candidates = [oci_runner] if oci_runner else _OCI_RUNNER_CANDIDATES
    for runner in candidates:
        path = _find_runner(runner)
        if path:
            report = ASH_LOGGER.debug if quiet else ASH_LOGGER.info
            report(f"Resolved OCI_RUNNER to: {path}")
            return path
    raise RuntimeError("Unable to resolve an OCI runner")


def _get_oci_wrapper_prefix() -> List[str]:
    """Return the OCI_RUNNER_WRAPPER as a list suitable for command prefix.

    Split on space, tab and newline only, as ./ash's prefix line splits it (bash's
    IFS): any other character, a vertical tab or a carriage return included, is part
    of a word there, so it is here too, and a wrapper of only those three is none.
    """
    oci_wrapper = os.environ.get("OCI_RUNNER_WRAPPER", "").strip(" \t\n")
    if not oci_wrapper:
        return []
    # A plain split on those three characters, as the wrappers split it: no quote
    # or backslash processing. A POSIX shlex removed backslashes (a Windows path
    # lost its separators), read quotes as grouping (a quoted word differed from
    # ./ash's) and raised ValueError on an unbalanced quote, which escaped
    # run_ash_container after the previous run's output had been cleared.
    return [word for word in re.split(r"[ \t\n]+", oci_wrapper) if word]


def sweep_leftovers_before_run(oci_runner: str | None) -> List[str]:
    """Remove the containers an earlier run left behind, resolving the runtime as a run does.

    The scan entry point calls this before it clears the previous run's declared
    outputs: a container that survived a die-now can write a declared output
    after that clear and before the read, and the run would vouch for those
    bytes. A host with no runtime has nothing to remove and is not an error.

    The runtime is looked for only once there is a record to act on, so a host
    with none starts nothing and logs nothing. The whole step is best effort:
    anything that goes wrong in it is one warning, and the scan goes on. A cancel
    or an interrupt is not an ``Exception`` and still ends the run.

    Returns:
        The names of the containers removed.
    """
    try:
        records = leftover_records()
        if not records:
            return []
        try:
            resolved = _resolve_oci_runner(oci_runner, quiet=True)
        except RuntimeError:
            return []
        removed = remove_leftovers([*_get_oci_wrapper_prefix(), resolved], records)
        if removed:
            ASH_LOGGER.info(
                f"Removed {len(removed)} container(s) left by an earlier run: "
                f"{', '.join(removed)}"
            )
        return removed
    except Exception as e:
        ASH_LOGGER.warning(f"Could not sweep leftover containers: {e}")
        return []


def _is_file(path: Path) -> bool:
    """``path.is_file()``, and False when the path cannot be looked at.

    On Python 3.10 to 3.13 ``is_file`` re-raises errors other than "no such file",
    such as EACCES under an unreadable parent or ESTALE on a stale NFS handle. (An
    offline Windows share's WinError 53 or 67 maps to ENOENT, which it already
    ignores.) A recorded path is outside ASH's control, so none of those may stop a
    run.
    """
    try:
        return path.is_file()
    except OSError:
        return False


def _is_ash_source_tree(path: Path) -> bool:
    """True if ``path`` holds a Dockerfile and a pyproject.toml named for ASH.

    The [project] name check keeps an unrelated tree that happens to sit at a
    recorded path from being built, such as a deleted build directory whose path
    was reused. It does not stop anyone who can write that path, who can write
    ASH's name into a pyproject.toml as well. A path that cannot be looked at is
    not a source tree.
    """
    name = _project_name(path)
    return name is not None and canonicalize_name(name) == "automated-security-helper"


def _project_name(path: Path) -> str | None:
    """The [project] name of a tree holding a Dockerfile and a pyproject.toml, if any.

    None when either file is missing or cannot be read, when the pyproject.toml is
    not TOML, or when it has no string [project] name.
    """
    if not _is_file(path.joinpath("Dockerfile")):
        return None
    try:
        project = _load_toml(path.joinpath("pyproject.toml")).get("project", {})
    except (OSError, ValueError, AttributeError):
        return None
    name = project.get("name") if isinstance(project, dict) else None
    return name if isinstance(name, str) else None


def _on_windows() -> bool:
    """True on Windows.

    A function, so a test can say which system this is without setting
    ``os.name``: on Python 3.10 and 3.11, every ``pathlib.Path`` made while
    ``os.name`` is wrong, pytest's own included, raises "cannot instantiate
    'WindowsPath' on your system".
    """
    return os.name == "nt"


def _file_url_path(url: str) -> Path | None:
    """The local path a ``file://`` URL names, or None for another machine's share.

    A ``file://`` URL with a host other than localhost names a share on another
    machine, which only Windows opens as a path (``\\\\host\\share\\...``). Elsewhere
    it is not followed: ``urlparse(url).path`` alone would drop the host and name a
    directory on this machine instead. None, too, for a URL the platform cannot
    turn into a path: on Python 3.14, ``url2pathname`` raises URLError (an
    OSError) for ``file:////server/share/...``.
    """
    try:
        parsed = urlparse(url)
        if parsed.netloc and parsed.netloc != "localhost":
            if not _on_windows():
                return None
            share_path = unquote(parsed.path)
            # `\\host` with no share after it is no share: on Python 3.10 and 3.11
            # PureWindowsPath("\\\\host") is the rooted, drive-relative "\host",
            # a directory on the current drive, and so is `\\host\\sub`, with an
            # empty share segment ("\host\sub"). An escaped slash or backslash
            # (%2F, %5C) can make that segment empty too, and so can a backslash
            # in the host, which urlparse keeps there: `file://work\/sub` has the
            # host "work\" and built `\\work\\sub`. So the server is the whole
            # host, with no separator in it, and the share is a non-empty segment.
            if "\\" in parsed.netloc or "/" in parsed.netloc:
                return None
            segments = share_path.replace("\\", "/").split("/")
            if len(segments) < 2 or not segments[1]:
                return None
            return Path("\\\\" + parsed.netloc + share_path.replace("/", "\\"))
        path = Path(url2pathname(parsed.path))
    except (OSError, ValueError):
        return None
    # `file://` and `file://localhost` hold no path, which Path() reads as "."
    # (on Windows, file:///C: gives the drive-relative "C:"): the working
    # directory, which is the project being scanned. A record names a directory
    # by its absolute path or names none.
    if not path.is_absolute():
        return None
    if _reaches_a_process_directory(path):
        return None
    return path


#: Directories whose entries name the running process's own working directory
#: and open files: /proc/self/cwd, /proc/thread-self/cwd, /dev/fd/N.
_PROCESS_DIRECTORIES = ("/proc", "/dev/fd")

#: Symbolic links followed before a lookup counts as a loop (Linux's own limit).
_SYMLINK_HOPS = 40


def _reaches_a_process_directory(path: Path) -> bool:
    """True when looking ``path`` up passes through /proc or /dev/fd.

    /proc/self/cwd (and /proc/thread-self/cwd, and /dev/fd/N for an open
    directory) name the directory ASH runs in by an absolute path, and docker
    resolves a build context through them: the scanned project again.

    The path is walked the way the kernel looks it up, one component at a time,
    following each symbolic link, so neither a ".." (``/dev/../proc``), nor a
    doubled slash, nor a link somewhere else that points at /proc/self/cwd
    hides it. Comparing the path's first components missed all three, and
    ``resolve()`` would miss the link too: it follows /proc/self/cwd itself to
    the working directory's own path. A lookup that loops counts as reaching it.
    Windows has neither directory.
    """
    if os.name == "nt":
        return False
    pending = [part for part in reversed(str(path).split("/")) if part]
    current = "/"
    hops = 0
    while pending:
        part = pending.pop()
        if part == ".":
            continue
        if part == "..":
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, part)
        if any(
            candidate == directory or candidate.startswith(directory + "/")
            for directory in _PROCESS_DIRECTORIES
        ):
            return True
        if os.path.islink(candidate):
            hops += 1
            try:
                target = os.readlink(candidate)
            except OSError:
                return True
            if hops > _SYMLINK_HOPS:
                return True
            pending.extend(piece for piece in reversed(target.split("/")) if piece)
            if target.startswith("/"):
                current = "/"
            continue
        current = candidate
    return False


def _source_tree_in(direct_url: object) -> Path | None:
    """The ASH source tree a direct_url.json record names, if it names one.

    A ``file://`` URL with ``dir_info`` is an install from a directory (``pip
    install <dir>``, ``uvx --from <dir>``, ``uv sync --no-editable``); one with
    ``archive_info`` names a wheel or an sdist, which is not a source tree, and
    neither is a directory that is gone or holds no ASH source tree now.
    """
    tree = _directory_in(direct_url)
    return tree if tree is not None and _is_ash_source_tree(tree) else None


def _directory_in(direct_url: object) -> Path | None:
    """The local directory a direct_url.json record says the package was built from."""
    if not isinstance(direct_url, dict) or "dir_info" not in direct_url:
        return None
    url = direct_url.get("url")
    if not isinstance(url, str) or not url.startswith("file://"):
        return None
    return _file_url_path(url)


def _recorded_direct_url() -> object:
    """This package's direct_url.json record, parsed, or None."""
    direct_url_json_path = _direct_url_json_path()
    if direct_url_json_path is None:
        return None
    try:
        return json.loads(direct_url_json_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _recorded_source_tree() -> Path | None:
    """The ASH source tree the installer recorded this package was built from, if any."""
    return _source_tree_in(_recorded_direct_url())


def _local_source_tree() -> Path:
    """The ASH source tree a LOCAL revision builds: its Dockerfile and its context.

    Found from the running package, never from the working directory: the working
    directory is usually the project being scanned, and a Dockerfile there is that
    project's. A clone the package runs from (an editable install) comes first,
    then the directory the installer recorded. pre-commit installs a python hook
    the second way, with ``pip install .`` in its clone of the hook repository, and
    runs it from the repository being scanned. The clone is the tree the package is
    running from, whatever its [project] name (a fork may rename it), as
    get_ash_revision's own test for LOCAL has it. A recorded directory is a path
    outside the package, so it has to be an ASH source tree
    (:func:`_is_ash_source_tree`).

    Raises:
        FileNotFoundError: With what to do instead, when the package came from a
            wheel or an index and no ASH source tree is recorded for it.
    """
    checkout = _checkout_root()
    if _is_checkout(checkout):
        return checkout
    recorded = _recorded_source_tree()
    if recorded is not None:
        return recorded
    directory = _directory_in(_recorded_direct_url())
    other_name = _project_name(directory) if directory is not None else None
    if other_name is not None:
        # ASH's own dist-info recorded this directory, and it now holds another
        # project: the directory was reused (a renamed fork installs under its own
        # dist-info name, so it never gets here). Quoted with repr, so a name with
        # a line break or an escape sequence prints as text.
        raise FileNotFoundError(
            "Dockerfile not found: a LOCAL revision builds the ASH source tree this "
            f"ASH was installed from. The installer recorded {str(directory)!r}, which "
            f"now holds the project {other_name!r}, not automated-security-helper, so "
            "it is not built as ASH's source. Reinstall ASH from its own source "
            "directory, build a released revision (--ash-revision-to-install <tag>), "
            "or pass --no-build to run an image you already have."
        )
    raise FileNotFoundError(
        "Dockerfile not found: a LOCAL revision builds the ASH source tree this ASH "
        f"was installed from, and this installation ({checkout.as_posix()!r}) has "
        "none beside it or recorded for it. Build a released revision instead "
        "(--ash-revision-to-install <tag>), reinstall ASH from its source directory, "
        "or pass --no-build to run an image you already have. For a fork that renames "
        "the project, install the fork's checkout in editable mode "
        "(pip install -e <checkout>) and run ASH from there."
    )


def _find_dockerfile(resolved_revision: str | None) -> Path:
    """Locate the Dockerfile to use for image builds.

    Always one of ASH's own. A pinned revision builds the Dockerfile packaged with
    ASH, which installs that revision from git; a LOCAL revision builds the
    Dockerfile at the root of the ASH source tree, see :func:`_local_source_tree`.
    The build context is the Dockerfile's directory (``_build_image``), so it is
    never the working directory either.

    Args:
        resolved_revision: The resolved ASH revision string (or None).

    Returns:
        Path to the Dockerfile.

    Raises:
        FileNotFoundError: When the Dockerfile cannot be located.
    """
    if resolved_revision == "LOCAL":
        dockerfile_path = _local_source_tree().joinpath("Dockerfile")
    else:
        dockerfile_path = ASH_ASSETS_DIR.joinpath("Dockerfile")

    if not dockerfile_path.is_file():
        raise FileNotFoundError(f"Dockerfile not found at {dockerfile_path}")

    return dockerfile_path


def _host_is_windows() -> bool:
    return platform.system().lower().startswith("win")


def _resolve_build_target(
    build_target: BuildTarget | str | None, custom_containerfile: str | None
) -> str:
    """The image stage to build and run: the one asked for, else the host's default.

    The default is ``non-root``, and ``ci`` on Windows, where the non-root user
    cannot write the bind-mounted output directory, so reports and logs would not
    be written. It is the same for ``ash --mode container`` and ``ash build-image``;
    an explicit stage wins on every platform.

    Environment variables play no part: ``CI``, ``IsCI``, ``ISCI`` and
    ``CODEBUILD_BUILD_ID`` do not change the stage, whatever their value. ``ci`` is
    built when it is asked for, or under ``--custom-containerfile``, which is
    documented to build on ``ci`` so the custom image keeps running as root.

    The name is returned in lower case: the build reads stage names in any case,
    so ``NON-ROOT`` from a library caller is ``non-root`` and is checked as such.
    """
    if custom_containerfile is not None:
        return BuildTarget.CI.value
    if build_target is None:
        return (
            BuildTarget.CI.value if _host_is_windows() else BuildTarget.NON_ROOT.value
        )
    name = build_target.value if hasattr(build_target, "value") else str(build_target)
    return name.lower()


def _non_root_stage_uid_refusal(
    build_target: str, container_uid: str, container_gid: str
) -> str | None:
    """Why a ``non-root`` build with these IDs cannot work, or None when it can.

    The ``non-root`` stage creates its user with ``adduser --uid <UID> --gid <GID>``.
    UID 0 is root, which already exists, so that build fails at that step after the
    whole ``core`` stage has been built; GID 0 is root's group, which would give the
    unprivileged user root's group rights over the image. A host running as root
    gets both by default (CI jobs often do), so either is refused here, before any
    build, with the two ways forward. Compared as numbers: the build reads
    ``UID=00`` as 0 too. Both are strings of digits by now (``run_ash_container``
    refuses any other).
    """
    if build_target != BuildTarget.NON_ROOT.value:
        return None

    def is_zero(digits: str) -> bool:
        # Without int(): a string of digits past the interpreter's conversion
        # limit raised ValueError here, after the pattern check had passed it.
        return digits.strip().lstrip("0") == ""

    if is_zero(container_uid):
        return (
            "The non-root image stage creates a user with UID 0, which is root: ASH "
            "is running as root, or --container-uid 0 was given. Pass --build-target "
            "ci to build the image that runs as root. Another --container-uid and "
            "--container-gid work only when the output directory is writable by that "
            "UID: the container runs as that user and writes its reports there."
        )
    if is_zero(container_gid):
        return (
            "The non-root image stage gives its user GID 0, which is root's group: "
            "ASH is running with GID 0, or --container-gid 0 was given. Pass "
            "--build-target ci to build the image that runs as root. Another "
            "--container-gid works only when the output directory is writable by the "
            "container's user, which writes its reports there."
        )
    return None


def _runner_supports_buildx(resolved_oci_runner: str) -> bool:
    """Whether the runner actually provides ``buildx``, probed once per path.

    The filename does not establish the capability. podman ships a
    ``podman-docker`` package whose ``/usr/bin/docker`` is a shim that execs
    podman, and ``_OCI_RUNNER_CANDIDATES`` reaches ``docker`` before ``podman``, so
    on such a host every name-based check passes for something that has no buildx
    at all. Asking the binary is the only thing that separates the two.

    Asked through ``OCI_RUNNER_WRAPPER``, as the build runs: a wrapper that runs
    the runtime as another user, or on another host, can have a buildx the bare
    binary does not, or none where the bare binary has one. The answer is kept
    per wrapper and path.
    """
    probe = [*_get_oci_wrapper_prefix(), resolved_oci_runner]
    key = " ".join(probe)
    if key in _BUILDX_SUPPORT_CACHE:
        return _BUILDX_SUPPORT_CACHE[key]

    supported = False
    try:
        result = subprocess_utils.run_command(
            [*probe, "buildx", "version"],
            capture_output=True,
            check=False,
            log_level=logging.DEBUG,
            timeout=30,
        )
        # Flags first: a run whose output ASH could not record can exit 0.
        supported = subprocess_utils.run_succeeded(result)
    except (OSError, SubprocessError) as e:
        # run_command with check=False already converts a timeout or a missing
        # binary into a non-zero CompletedProcess, so this is belt and braces.
        ASH_LOGGER.debug(f"buildx probe for {resolved_oci_runner} failed: {e}")

    if not supported:
        ASH_LOGGER.debug(
            f"{resolved_oci_runner} does not provide buildx -- skipping layer cache"
        )
    _BUILDX_SUPPORT_CACHE[key] = supported
    return supported


def _gha_layer_cache_args(
    resolved_oci_runner: str,
    build_target: str,
    force: bool,
    offline: bool,
) -> List[str]:
    """Return buildx flags that read and write image layers via the GitHub Actions cache.

    Returns an empty list whenever the cache is unusable, in which case the caller
    keeps using a plain ``<runtime> build`` and nothing about the build changes.

    Why each guard exists:

    - docker only. ``type=gha`` is a buildx cache backend. podman and finch expose
      only registry-backed caches, so there is nothing equivalent to offer them.
    - And docker in fact, not just in name. See ``_runner_supports_buildx``.
    - Only inside a GitHub Actions run. The exporter authenticates with
      ACTIONS_RUNTIME_TOKEN and talks to ACTIONS_CACHE_URL (protocol v1) or
      ACTIONS_RESULTS_URL (v2). Note that Actions does not place these in the
      environment of ``run:`` steps by default, so a workflow has to export them
      deliberately; absent them this returns nothing rather than failing a build.
    - Never with ``force``. ``force`` means ``--no-cache``, i.e. rebuild from
      scratch, so reading from a cache would contradict the caller's intent.

    Nothing is published. ``type=gha`` writes to the Actions cache service, not to
    a registry, and the entries are scoped to the repository and readable only with
    the run's token. Distributing an image is a separate ``--push`` operation that
    this does not perform.
    """
    # Compare the final path component, not the whole string. The runner arrives
    # here already resolved: _resolve_oci_runner returns find_executable's output,
    # which is a full path such as /usr/bin/docker, and carries a .exe suffix on
    # Windows. ``stem`` reduces every one of those shapes -- and a bare name -- to
    # ``docker``, while still declining neighbors like /usr/bin/docker-compose
    # that a substring test would wrongly accept.
    if Path(resolved_oci_runner).stem != "docker":
        return []
    if force:
        return []
    if os.environ.get("ASH_DISABLE_GHA_BUILD_CACHE", "").strip():
        return []
    if not os.environ.get("ACTIONS_RUNTIME_TOKEN"):
        return []
    if not (
        os.environ.get("ACTIONS_CACHE_URL") or os.environ.get("ACTIONS_RESULTS_URL")
    ):
        return []
    # Last, because it is the only guard that shells out. By here the environment
    # has already said we are inside Actions, so this runs about once per build.
    if not _runner_supports_buildx(resolved_oci_runner):
        return []

    # One scope per distinct set of layers. build_target is in the key because the
    # two stages end in different layers (`non-root` adds a user and installs the
    # Python tools again for it), and it is whatever the caller asked for: CI
    # variables do not choose it. The other two components matter as much: the CPU
    # architecture -- buildkit requests a different manifest per arch, so those
    # entries can never be shared -- and OFFLINE, which the Dockerfile consumes near
    # the top and which therefore invalidates nearly every layer below it. Without
    # all three, the cells overwrite one another and buildkit keeps only whichever
    # finished last.
    scope = (
        f"ash-{build_target}-{platform.machine()}-{'offline' if offline else 'online'}"
    )
    # Cache service v2 whenever the runner offers it. buildkit's gha backend
    # defaults to v1 unless told otherwise, and on github.com the v1 service no
    # longer answers: every import and export in this repository's scan legs came
    # back `failed to parse error response 400: Our services aren't available
    # right now` (run 37499915881, job 112397773175), and ignore-error turned that
    # into a silent, total cache miss on every build. ACTIONS_RESULTS_URL is the v2
    # endpoint, so its presence is what selects v2; a runner that only provides
    # ACTIONS_CACHE_URL (an older GitHub Enterprise Server) keeps v1.
    version = ",version=2" if os.environ.get("ACTIONS_RESULTS_URL") else ""
    args = ["--cache-from", f"type=gha{version},scope={scope}"]

    # Which layers to export, if any: ASH_GHA_BUILD_CACHE_EXPORT is none, min or
    # max, and unset means min.
    #
    # min stays the default. The Actions cache is capped at 10 GB per repository
    # and evicts by least-recent access across every workflow, so exporting each
    # intermediate stage of a multi-GB scanner image, once per scope, can evict
    # caches unrelated jobs restore. A caller opts into max deliberately, and
    # into none to read without writing. This repository's CI exports max from
    # pushes to main and nothing from pull requests -- the maintainer's decision
    # recorded in .github/scripts/assert-publish-surfaces.py -- so every pull
    # request reads the layers main wrote and none adds its own copy.
    #
    # An unrecognized value exports nothing rather than guessing: the cost is a
    # cold cache, never an unintended write.
    export = os.environ.get("ASH_GHA_BUILD_CACHE_EXPORT", "").strip().lower() or "min"
    if export not in ("none", "min", "max"):
        ASH_LOGGER.warning(
            f"ASH_GHA_BUILD_CACHE_EXPORT={export!r} is not none, min or max; "
            "not exporting the layer cache"
        )
        export = "none"
    if export != "none":
        # ignore-error keeps a cache-service outage from failing the build. A
        # transient 400 from this export step took three scan cells down, while
        # the import above degraded to a plain cache miss on its own.
        args += [
            "--cache-to",
            f"type=gha{version},mode={export},ignore-error=true,scope={scope}",
        ]
    return args


# The build-context name the cached base-image layout is attached under, and therefore the value
# `FROM ${BASE_IMAGE}` is pointed at. Not a registry reference: nothing named this exists on any
# registry, so a builder that ignored the context and went to the network would fail rather
# than quietly resolve something.
BASE_OCI_LAYOUT_CONTEXT = "ash-base-image"
_BASE_OCI_LAYOUT_VALUE = re.compile(r"^(?P<dir>.+)@(?P<digest>sha256:[0-9a-f]{64})$")


def _base_oci_layout_args(resolved_oci_runner: str, buildx: bool) -> List[str]:
    """Build arguments that hand the build the base image from a verified OCI layout.

    ``ASH_BASE_OCI_LAYOUT=<layout dir>@<arch manifest digest>`` is set by
    ``.github/actions/prepull-base-image`` on a cache hit, after it has verified every blob in
    the layout against the Dockerfile's pinned digest. What each runtime needs differs, and the
    action's header carries the measurements behind each row:

    - ``docker buildx build`` (a docker-container builder, which cannot see the engine's image
      store): ``--build-context ash-base-image=oci-layout://DIR@DIGEST`` plus
      ``--build-arg BASE_IMAGE=ash-base-image``.
    - plain ``docker build`` (the docker driver): nothing. That driver turns an oci-layout
      context into a registry lookup, so the action loads the layout into the engine instead
      and the driver's default prefers the local image.
    - nerdctl and finch: the same context spelled ``oci-layout://DIR`` -- nerdctl treats
      everything after the prefix as the path and reads the image from index.json -- plus
      ``--pull=false``, which nerdctl maps to ``image-resolve-mode=local``.
    - podman: nothing. It has no oci-layout build context; the action imports the layout into
      podman's store and ``podman build``'s default ``--pull=missing`` uses it.

    Empty when the variable is unset or empty. A malformed value raises rather than being
    ignored, because ignoring it would send the build to the registry the variable exists to
    avoid, with nothing in the log saying why.
    """
    value = os.environ.get("ASH_BASE_OCI_LAYOUT", "").strip()
    if not value:
        return []
    match = _BASE_OCI_LAYOUT_VALUE.match(value)
    if match is None:
        raise ValueError(
            f"ASH_BASE_OCI_LAYOUT is '{value}', which is not <layout dir>@sha256:<64 hex>. "
            "It is set by .github/actions/prepull-base-image; unset it to build from the "
            "Dockerfile's own base image reference."
        )
    layout_dir, digest = match.group("dir"), match.group("digest")
    runner = Path(resolved_oci_runner).stem
    if runner == "docker":
        if not buildx:
            return []
        context = f"oci-layout://{layout_dir}@{digest}"
        extra: List[str] = []
    elif runner in ("nerdctl", "finch"):
        context = f"oci-layout://{layout_dir}"
        extra = ["--pull=false"]
    else:
        return []
    return [
        "--build-context",
        f"{BASE_OCI_LAYOUT_CONTEXT}={context}",
        "--build-arg",
        f"BASE_IMAGE={BASE_OCI_LAYOUT_CONTEXT}",
        *extra,
    ]


def _build_date_epoch() -> int:
    """The BUILD_DATE_EPOCH of an image build: UTC midnight of today, in epoch seconds.

    ``now - now % 86400`` is exact because POSIX time has no leap seconds, and it is
    the same arithmetic ./ash, utils/ash_helpers.ps1 and the deploy/ image builds use,
    so every entrypoint passes the same value on a given day.
    """
    now = int(datetime.now(timezone.utc).timestamp())
    return now - now % 86400


def _build_image(
    oci_command_prefix: List[str],
    resolved_oci_runner: str,
    dockerfile_path: Path,
    image_name: str,
    build_target: str,
    container_uid: str,
    container_gid: str,
    resolved_revision: str | None,
    offline: bool,
    offline_semgrep_rulesets: str,
    force: bool,
    quiet: bool,
    custom_build_arg: List[str],
    debug: bool,
) -> None:
    """Build the base ASH container image.

    Raises:
        CalledProcessError: On non-zero exit from the build command.
        Exception: On any other build failure.
    """
    echo(
        f"Building image {image_name} -- this may take a few minutes during the first build..."
    )

    # Layer caching needs buildx: type=gha is not supported by the default docker
    # driver. buildx also leaves the local image store untouched unless asked, so
    # --load is required or the image would not exist for the subsequent run.
    cache_args = _gha_layer_cache_args(
        resolved_oci_runner, build_target, force, offline
    )
    if cache_args:
        build_cmd = [
            *oci_command_prefix,
            resolved_oci_runner,
            "buildx",
            "build",
            "--load",
        ]
    else:
        build_cmd = [*oci_command_prefix, resolved_oci_runner, "build"]
    build_cmd.extend(cache_args)
    build_cmd.extend(["--build-arg", f"UID={container_uid}"])
    build_cmd.extend(["--build-arg", f"GID={container_gid}"])
    # A branch moves, but the Dockerfile's clone step is the same command every time,
    # so without a new value for this ARG the build cache served the first clone of
    # the branch to every later build (--force aside). A tag or a commit id clones the
    # same tree each time and gets none, so its clone stays cached. Neither does a
    # build whose context is ASH's own tree, which the clone step builds instead of
    # cloning.
    if _revision_moves(resolved_revision) and not _is_ash_source_tree(
        dockerfile_path.parent
    ):
        build_cmd.extend(
            [
                "--build-arg",
                f"{CLONE_DATE_BUILD_ARG}={int(datetime.now().timestamp())}",
            ]
        )
    build_cmd.extend(
        [
            "--tag",
            image_name,
            "--target",
            build_target,
            "--file",
            dockerfile_path.as_posix(),
            "--build-arg",
            f"INSTALL_ASH_REVISION={resolved_revision}",
            "--build-arg",
            f"OFFLINE={'YES' if offline else 'NO'}",
            "--build-arg",
            f"OFFLINE_SEMGREP_RULESETS={offline_semgrep_rulesets}",
            # A new value re-runs the Dockerfile's core stage from its apt-get
            # upgrade step down, offline download included; see ARG BUILD_DATE_EPOCH
            # there. One value per UTC day, so rebuilds on the same day come from the
            # layer cache, and OS packages and offline databases are at most a day old.
            "--build-arg",
            f"BUILD_DATE_EPOCH={_build_date_epoch()}",
        ]
    )

    # ASH_BASE_IMAGE_OVERRIDE redirects `FROM ${BASE_IMAGE}` at the registry that actually
    # answered, and is set by .github/actions/prepull-base-image when ECR Public refuses the
    # base image and Docker Hub serves it instead. It is a digest-pinned reference, so this
    # path is more tightly pinned than the Dockerfile's own tag default, not less.
    #
    # It has to be a build-arg rather than only a local tag under the ECR name. BuildKit does
    # consult a local store after a registry refusal, but only when the worker HAS one:
    # `sourceresolver/imageresolver.go` gates that recovery behind
    # `rm != ResolveModeDefault || is.ImageStore == nil`, and `worker/runc/runc.go` sets
    # `ImageStore: nil, // explicitly`. A `docker buildx build` on a docker-container driver
    # runs buildkitd in its own container with exactly that worker, so it never sees the host's
    # image store -- measured: a build with the tag present still died at `FROM` asking the
    # refusing registry. That driver cannot be configured out of it from here, so changing what
    # FROM asks for is the one mechanism every runtime and every driver honours. See
    # .github/actions/prepull-base-image for the full per-runtime table.
    #
    # Emitted BEFORE custom_build_arg, because a duplicate --build-arg is last-wins (measured
    # on docker 25.0.16), so an explicit `--custom-build-arg BASE_IMAGE=...` from the caller
    # still overrides this CI fallback rather than being silently discarded.
    #
    # ASH_BASE_OCI_LAYOUT, when this runtime can take it, replaces the override: it is only set
    # on a cache hit, where the pre-pull made no registry call and exported no override, so the
    # two do not meet in CI. If both were set by hand, the verified layout wins where this
    # runtime can take it (docker needs buildx for an oci-layout context, see
    # _base_oci_layout_args), since it names content the override would have to fetch; where it
    # cannot, the layout is already in the engine's store and the override applies.
    base_layout_args = _base_oci_layout_args(
        resolved_oci_runner, buildx=bool(cache_args)
    )
    base_image_override = os.environ.get("ASH_BASE_IMAGE_OVERRIDE", "").strip()
    if base_layout_args:
        echo(
            "Base image taken from the verified OCI layout named by ASH_BASE_OCI_LAYOUT, "
            "with no registry call."
        )
        build_cmd.extend(base_layout_args)
    elif base_image_override:
        echo(
            f"Base image redirected to {base_image_override} "
            "by ASH_BASE_IMAGE_OVERRIDE in the environment."
        )
        build_cmd.extend(["--build-arg", f"BASE_IMAGE={base_image_override}"])

    # `--custom-build-arg FOO=bar` was threaded from the CLI through run_ash_scan into this
    # function's signature and then never appended to the command, so every value a caller
    # passed was silently dropped. Appended here rather than alongside the fixed build-args
    # above so that it lands last and therefore wins any collision with them.
    for build_arg in custom_build_arg:
        build_cmd.extend(["--build-arg", build_arg])

    extra_args: List[str] = []
    if force:
        extra_args.append("--no-cache")
    if quiet:
        extra_args.append("-q")
    build_cmd.extend(extra_args)
    build_cmd.append(dockerfile_path.parent.as_posix())

    if debug:
        echo(f"Running build command: {_shown_command_text(build_cmd)}")

    result = run_cmd_direct(build_cmd, debug=debug)

    if debug:
        echo(f"Build completed with return code: {result.returncode}")


#: A ``FROM <image> AS <name>`` line, with any ``--platform``-style flags.
_FROM_AS_STAGE = re.compile(
    r"^[ \t]*FROM[ \t]+(?:--\S+[ \t]+)*\S+[ \t]+AS[ \t]+([A-Za-z0-9_.-]+)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


def _custom_containerfile_stage(
    build_target: BuildTarget | str | None, custom_containerfile: str | None
) -> str | None:
    """The stage of ``--custom-containerfile`` to build, or None for the whole file.

    The custom file is built on the ``ci`` image. ``--build-target non-root`` with it
    names the custom file's own ``non-root`` stage, which then has to exist
    (:func:`_custom_containerfile_stage_refusal`).
    """
    if custom_containerfile is None or build_target is None:
        return None
    name = build_target.value if hasattr(build_target, "value") else str(build_target)
    return BuildTarget.NON_ROOT.value if name.lower() == "non-root" else None


def _custom_containerfile_stage_refusal(
    build_target: BuildTarget | str | None, custom_containerfile: str | None
) -> str | None:
    """Why ``--build-target non-root`` cannot be built from this custom file, or None."""
    stage = _custom_containerfile_stage(build_target, custom_containerfile)
    # _custom_containerfile_stage is None without a custom file; the second test
    # says so where the type checker can see it.
    if stage is None or custom_containerfile is None:
        return None
    try:
        # utf-8-sig: a byte order mark on the first line is not part of the FROM
        # it starts, and the build reads the line past it.
        text = Path(custom_containerfile).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return None  # the build reports a file it cannot read
    # As the build reads the file: a comment line is dropped, wherever it is
    # (one inside a continued instruction included), and a line continued with
    # a backslash, blanks after it or not, is one instruction with the next.
    text = re.sub(r"(?m)^[ \t]*#[^\n]*\n?", "", text)
    text = re.sub(r"\\[ \t]*\r?\n", " ", text)
    if any(name.lower() == stage for name in _FROM_AS_STAGE.findall(text)):
        return None
    return (
        f"--build-target non-root was given with --custom-containerfile "
        f"{custom_containerfile}, which defines no stage named non-root. The custom "
        "image is built on the ci stage, which runs as root, so it would not be the "
        "non-root image asked for. Leave out --build-target to build the custom file "
        "as it is, on ci, or give it a stage named non-root."
    )


def _build_custom_image(
    oci_command_prefix: List[str],
    resolved_oci_runner: str,
    base_image_name: str,
    custom_containerfile: str,
    quiet: bool,
    debug: bool,
    target: str | None = None,
    force: bool = False,
) -> str:
    """Build a custom image layered on top of the base ASH image.

    Args:
        base_image_name: Name of the base image to build on top of.
        custom_containerfile: Path to the custom Containerfile/Dockerfile.
        target: The custom file's stage to build, or None for the whole file.
        force: Build without the layer cache (``--no-cache``), as ``--force`` builds
            the base image: the custom file's own stages are otherwise served from
            the cache whatever the base image became.

    Returns:
        The image name of the custom image.

    Raises:
        FileNotFoundError: When the custom containerfile does not exist.
        CalledProcessError: On non-zero exit from the build command.
    """
    if not Path(custom_containerfile).exists():
        raise FileNotFoundError(
            f"Custom containerfile not found at {custom_containerfile}"
        )

    custom_build_cmd = [*oci_command_prefix, resolved_oci_runner, "build"]
    custom_build_cmd.extend(
        [
            "--tag",
            "automated-security-helper:custom",
            "--file",
            Path(custom_containerfile).as_posix(),
            "--build-arg",
            f"ASH_BASE_IMAGE={base_image_name}",
        ]
    )
    if target is not None:
        custom_build_cmd.extend(["--target", target])
    if force:
        custom_build_cmd.append("--no-cache")
    if quiet:
        custom_build_cmd.append("-q")
    custom_build_cmd.append(Path(custom_containerfile).parent.as_posix())

    result = run_cmd_direct(custom_build_cmd, debug=debug)

    if debug:
        echo(f"Custom build completed with return code: {result.returncode}")

    return "automated-security-helper:custom"


#: Characters the runner's ``--mount`` syntax cannot carry in a path. Its value is
#: read as comma-separated ``key=value`` fields (CSV), so a comma starts a field of
#: its own (``a,b`` is read as ``a`` and a field ``b``), a double quote starts CSV
#: quoting, and a line break ends the argument for a runner that reads it a line at
#: a time.
_UNMOUNTABLE_CHARACTERS = (",", '"', "\n", "\r")


class ContainerInputError(ValueError):
    """An input the scan inside the container could not be given as it is on the host."""


class UnmountablePathError(ContainerInputError):
    """A host path that would be mounted holds a character ``--mount`` cannot carry."""


class ContainerOutputLinkRefused(ContainerInputError):
    """The output directory mounted at ``/out`` is a symlink or is reached through one.

    ``found`` describes the link as the general check describes it
    (utils/output_dir_links.linked_output_component), and the message adds why
    container mode refuses it and what to use instead.
    """

    def __init__(self, found: str, message: str):
        super().__init__(message)
        self.found = found


class MountPathNotUtf8Error(UnmountablePathError):
    """A host path that would be mounted is not UTF-8.

    The runtime takes a mount's source as UTF-8 text. Measured with docker 25: the
    daemon received a byte that is not UTF-8 as U+FFFD, then refused the mount
    ("bind source path does not exist"), or, where a path of that other name
    existed, mounted that one, so the container read a file or directory other
    than the one named. Exit 3, as for any other path the runner cannot be handed.
    """


#: How the refusal of a mounted path that is not UTF-8 names the path, what the runtime
#: would mount instead, and what to do, by the label it is checked under. The two
#: directories are worded as ``ash scan`` words them; a config file the same way, as a
#: file.
_NOT_UTF8_REFUSAL = {
    "source directory": (
        "The directory to scan",
        "directory",
        "Rename the directory whose name is not UTF-8.",
    ),
    "output directory": (
        "The output directory",
        "directory",
        "Choose an --output-dir whose path is UTF-8.",
    ),
}
_NOT_UTF8_FILE_WAY_OUT = (
    "Rename the file, or the directory holding it, whose name is not UTF-8."
)


def _readable_environment_values() -> Tuple[str, ...]:
    """Every value a config file can read from this environment, set and non-blank.

    The loader resolves ``${NAME}`` only for the names
    ``is_readable_environment_name`` admits (the one rule both share), so a
    message rendered with these values hidden cannot quote anything a chain
    read from the environment -- used where a failure's text may quote a
    resolved entry and the chain's own view of which names it read is not
    available (the chain did not resolve).

    Short flag-shaped values ("1", "true") are hidden too: in the single
    chain-failure debug line that trades a little noise for leak safety, the
    right direction to err in.
    """
    return tuple(
        value
        for name, value in snapshot_environ().items()
        if value.strip() and is_readable_environment_name(name)
    )


def _require_mountable(label: str, path: Path | str, shown: str | None = None) -> None:
    """Refuse a path the runner would read as something other than that path.

    A character ``--mount`` cannot carry (UnmountablePathError), and a path that is
    not UTF-8, whose undecodable bytes Python holds as lone surrogates
    (MountPathNotUtf8Error). Either refuses the run with exit 3. The path is shown as
    ``repr`` shows it, so such a byte reads as ``\\udcNN`` -- unless the caller gives
    *shown*, the name a message may use for it: a chain path reached through an
    entry that reads the environment holds the variable's value, so the refusal
    names it the way the chain views do (``_chain_placements_shown``) while the
    check still judges the real path.
    """
    text = str(path)
    named = repr(text) if shown is None else shown
    if any(character in text for character in _UNMOUNTABLE_CHARACTERS):
        raise UnmountablePathError(
            f"The {label} {named} cannot be handed to the container runner: --mount "
            "reads its value as comma-separated fields, so a path holding a comma, a "
            "double quote or a line break would be read as something else. Rename it, "
            "or choose another path."
        )
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        described, kind, way_out = _NOT_UTF8_REFUSAL.get(
            label, (f"The {label}", "file", _NOT_UTF8_FILE_WAY_OUT)
        )
        raise MountPathNotUtf8Error(
            f"ERROR (3) {described}, {named}, has a path that is not UTF-8. "
            "Container mode bind-mounts it, and the container runtime takes a mount's "
            f"path as UTF-8 text: it would refuse the mount, or mount a different "
            f"{kind} whose name it reads the same way. {way_out}"
        ) from None


def _require_mountable_directories(
    source_dir: Path | str, output_dir: Path | str
) -> None:
    """Check the two directories a run mounts, as they will be mounted, before
    anything is created or run.

    A path holding a NUL byte is refused first, as UnmountablePathError: no path can
    hold one and no argument can carry one, and resolving it would raise ValueError
    out of the check. Only a caller of the API can pass one.
    """
    for label, path in (
        ("source directory", source_dir),
        ("output directory", output_dir),
    ):
        text = str(path)
        if "\0" in text:
            raise UnmountablePathError(
                f"The {label} {text!r} cannot be handed to the container runner: it "
                "holds a NUL byte, which no path and no command-line argument can "
                "hold. Choose another path."
            )
        from automated_security_helper.utils.error_text import text_without_values

        # The check runs on the resolved path, which is what the mount uses;
        # the refusal names the directory as the operator gave it (their own
        # command line's or environment's text), since that is the spelling
        # they can act on, with the resolved path beside it when a link
        # carried the refused character in. Each spelling is shown with the
        # environment's readable values hidden, so a directory an environment
        # value chose never prints raw in either position.
        resolved = Path(path).resolve()
        hidden = _readable_environment_values()
        given_shown = text_without_values(repr(text), hidden)
        shown = (
            given_shown
            if str(resolved) == text
            else f"{given_shown} ({text_without_values(repr(str(resolved)), hidden)})"
        )
        _require_mountable(label, resolved, shown=shown)


#: Where container mode mounts a ``--config`` kept outside the source directory,
#: with each base it extends where the file that extends it names it.
CONTAINER_CONFIG_ROOT = "/ash-config"
#: Where workspace mode mounts the operator's ``--config``: the same place, with
#: each base it extends where the file that extends it names it.
OPERATOR_CONFIG_MOUNT = CONTAINER_CONFIG_ROOT
#: The same for a workspace policy file kept outside the workspace root.
CONTAINER_WORKSPACE_CONFIG_ROOT = "/ash-workspace-config"
#: The same for the file the host's ``ASH_CONFIG`` names, with each base it
#: extends; see :func:`_host_ash_config`.
CONTAINER_ENV_CONFIG_ROOT = "/ash-env-config"

#: Tells the scan inside the container that its --config was written by the
#: repository being scanned, with every file it extends; see _config_marks.
CONFIG_FROM_SCANNED_REPOSITORY_FLAG = "--config-from-scanned-repository"
#: Tells the scan inside the container that one file the --config extends was
#: written by the repository being scanned, by its container path; see _config_marks.
CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG = "--config-file-from-scanned-repository"
#: Tells the scan inside the container that one file the --config or ASH_CONFIG
#: chain holds is in a git checkout other than the scanned one, by its container
#: path; see _another_checkout_marks.
CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG = "--config-file-from-another-checkout"
#: Tells the scan inside the container where the file the host's ASH_CONFIG names
#: is mounted, so it reads that file as ASH_CONFIG; see _host_ash_config.
ASH_CONFIG_FROM_HOST_FLAG = "--ash-config-from-host"


def _real_path(path: str | Path) -> Path:
    return Path(os.path.realpath(path))


def _scanned_tree_roots(source_dir: Path) -> List[Path]:
    """The scanned tree, under every name it has.

    The outermost git checkout holding the source directory, from each of the
    directory's names (as given, resolved, and through ``$PWD``), or the
    directory itself outside every checkout: ``config/sandbox_grants.scanned_trees``,
    the trees the membership judgments (``files_inside``) hold a local scan's
    config chain to.
    """
    from automated_security_helper.config.sandbox_grants import scanned_trees

    return scanned_trees(Path(source_dir))


def _name_from_the_logical_directory(name: str | Path) -> Path | None:
    """A relative *name* as ``$PWD`` spells it, when that is another spelling.

    ``os.getcwd()`` and the kernel read a relative name from the physical working
    directory. The shell stands in the directory ``$PWD`` names, and when that
    reaches the same directory through a link (a link the scanned tree holds,
    say) the same name read from there walks that link. None when the name is
    absolute, when ``$PWD`` is unset, relative, or names another directory, and
    when it is the physical path itself: nothing is then judged twice.
    """
    if os.path.isabs(name):
        return None
    pwd = os.environ.get("PWD")
    if not pwd or not os.path.isabs(pwd):
        return None
    try:
        physical = os.getcwd()
        if pwd == physical or not os.path.samefile(pwd, physical):
            return None
    except OSError:
        return None
    return Path(pwd) / name


def _repository_written(path: Path, source_dir: Path) -> bool:
    """Whether a local scan of *source_dir* counts *path* as the repository's.

    The rule ``resolve_config`` applies to a scan's config files: inside the
    scanned trees (``sandbox_grants.files_inside`` over ``scanned_trees``),
    judged both by where *path* resolves to and by where its name and the
    links resolving it sit. A relative name is judged from the physical working
    directory and, when ``$PWD`` spells that directory another way, from there
    as well (:func:`_name_from_the_logical_directory`). A file in some other
    checkout is not the scanned tree's: it cannot grant, as on the host
    (``resolve_config._with_outside_files``), but it is not a member of the tree
    either, so :func:`_another_checkout_marks` marks it on its own.
    """
    from automated_security_helper.config.sandbox_grants import (
        files_inside,
        scanned_trees,
    )

    path = Path(path)
    trees = scanned_trees(Path(source_dir))
    names = [path]
    logical = _name_from_the_logical_directory(path)
    if logical is not None:
        names.append(logical)
    return bool(files_inside([path], trees, named=names))


def _named_in_a_scanned_tree(named: Path, trees: List[Path]) -> bool:
    """Whether the operator's spelling names a path the scanned tree resolves.

    The absolute, uncollapsed spelling is walked component by component, as the
    filesystem walks it, and the first link that sits inside a scanned tree
    decides: the rest of the name is then the tree's to steer, so the name is
    the tree's -- ``src/L/../../secret.yaml`` with ``L`` a tree link counts,
    because the link's target decides where ``..`` lands. A link outside every
    tree is collapsed with ``os.path.realpath`` and the walk goes on from
    where it lands: a directory link continues the walk from the real
    directory, and a final-component file link collapses its whole chain. The
    host's own ``/tmp`` or ``/home`` is often such a link, and a walk that
    stopped at one never reached the tree, so an ancestor link above it hid
    every tree link behind it; an operator's own link into the tree ends the
    same way, judged by the tree it lands in. A tree link that lies only
    inside a collapsed chain does not make the name the tree's: whether the
    config is repository-written is the marking machinery's to judge, not this
    gate's. A plain ``..`` through real directories is the operator's own
    arithmetic, so with no tree link on the way the name is the tree's exactly
    when the walked path ends inside one -- and then its real path is that
    same path, so the caller's outside-the-tree check cannot fire on it. A
    collapse that cannot resolve (the result is still a link: a link loop, or a
    link the process cannot read; or a component the process cannot stat) is
    refused with ``ContainerInputError``
    rather than walked past, because the mount would otherwise carry the
    unresolved link path and the runner, not ASH, would decide what it names.
    """
    from automated_security_helper.config.config_sources import _is_a_link
    from automated_security_helper.config.sandbox_grants import is_within

    current = Path(named.parts[0])
    for position, part in enumerate(named.parts[1:], start=1):
        if part == ".":
            continue
        if part == "..":
            current = current.parent
            continue
        current = current / part
        # *current* is rebased onto real paths each time a link is collapsed,
        # so it can carry bytes a repository chose. A refusal names the
        # operator's own spelling of the same component instead: the given
        # name up to and including this part.
        spelled = Path(*named.parts[: position + 1])
        try:
            os.lstat(current)
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError:
            # A component the process cannot even stat (a directory it cannot
            # search) may hide a link: the walk cannot decide the rest.
            raise _unresolvable_name(named, spelled, _UNSEARCHABLE_DIRECTORY) from None
        # The repo's own link test, not os.path.islink: a Windows junction is
        # a reparse point islink never reports. This gate is a refusal, so
        # reading every reparse point as a link fails closed; the scan-set
        # walk deliberately does not (sandbox_grants.py on OneDrive
        # placeholders), which is why the two are not shared.
        if _is_a_link(current):
            # Judged by where the link SITS -- its directory, which the walk
            # has already resolved -- never by where it points, which
            # is_within on the link itself would read instead.
            if any(is_within(current.parent, tree) for tree in trees):
                return True
            # Outside every tree the link is not the tree's to steer, but it
            # settles nothing either: the walk follows it and keeps judging
            # the rest of the name where it lands. A tree link inside the
            # collapsed chain is not judged here; it demotes trust through
            # the config marks instead.
            try:
                current = Path(os.path.realpath(current))
            except (OSError, ValueError):
                # realpath follows links itself, and a link it cannot read
                # raises out of the collapse: the walk cannot decide the rest.
                # A platform can also raise ValueError for an entry it
                # reports as a link but cannot read as one (a reparse point
                # that is not a symbolic link); same answer.
                raise _unresolvable_name(named, spelled, _UNREADABLE_LINK) from None
            # realpath resolves every chain it can, so a result that is still
            # a link means the collapse could not decide: a link loop, or a
            # link the process cannot read, or a landing place it cannot stat.
            # The walk does not go on past it.
            if _collapse_left_undecided(current):
                raise _unresolvable_name(named, spelled, _LOOP_OR_UNEXAMINABLE_LANDING)
    return any(is_within(current, tree) for tree in trees)


def _collapse_left_undecided(place: Path) -> bool:
    """Whether the place a collapse landed on is still a link, or unreadable.

    Not ``_is_a_link``: that reads any Windows reparse point as a link, and
    a OneDrive placeholder or a deduplicated file is one that resolves to
    itself. Landing on it is a settled answer, not a loop. Only a name
    surrogate (a symlink, a junction) counts as a link left standing, and any
    lookup failure but "absent" cannot be told apart from a link above the
    place that could not be followed.
    """
    from automated_security_helper.config.config_sources import _is_a_link_by
    from automated_security_helper.utils.scanned_tree import _is_link_stat

    return _is_a_link_by(place, _is_link_stat)


#: Why a name's walk could not be decided, one per place it stops
#: (:func:`_named_in_a_scanned_tree`), so the refusal sends the operator to the
#: thing that is wrong.
_UNSEARCHABLE_DIRECTORY = "a directory on the way cannot be searched"
_UNREADABLE_LINK = "a link on the way cannot be read"
_LOOP_OR_UNEXAMINABLE_LANDING = (
    "a link loop, a link that cannot be read, or the place a link lands on "
    "cannot be examined"
)


def _unresolvable_name(named: Path, at: Path, reason: str) -> ContainerInputError:
    """The refusal for a name whose walk cannot be decided at *at*, for *reason*.

    *at* is the operator's spelling of the component, never a path rebased
    through a collapsed link. The text is passed through the control-character
    pass as a whole, so no arm of it can carry a raw control character.
    """
    from automated_security_helper.utils.terminal_text import (
        raw_controls_on_one_line,
    )

    return ContainerInputError(
        raw_controls_on_one_line(
            f"The name '{named}' goes through '{at}', which cannot be resolved. "
            f"ASH does not hand the container runner a name it cannot resolve: "
            f"{reason}. Name the file itself."
        )
    )


def _refuse_config_linked_out_of_the_tree(
    config: str, source_dir: Path, label: str = "config file"
) -> None:
    """Refuse a file named inside the scanned tree whose real path is outside it.

    The scanned tree is the outermost checkout at or above the source directory (the
    workspace root, in workspace mode), and the source directory itself
    (``_scanned_tree_roots``). A config or workspace policy path inside it is mounted
    only when its real path, every link on the way resolved, is inside it too; a link
    that stays inside the tree is followed. A path outside the tree is followed
    wherever it points. Whether the name is the tree's is judged on the
    spelling the operator gave, walked as the filesystem walks it
    (:func:`_named_in_a_scanned_tree`), never by the name collapsed lexically,
    which read a spelling through a repository-written link and back out with
    ``..`` as a path outside the tree. The gate judges the name the operator
    gave: a link that sits inside a scanned tree makes the name the tree's, and
    a link outside every tree is collapsed with ``os.path.realpath`` (a
    directory link continues the walk from the real directory; a
    final-component file link collapses the whole chain). Refusal is only for
    a name that is the tree's, spelled into the tree or steered into it by a
    directory alias, resolving outside it. A tree link that lies only inside a
    collapsed chain does not make the name the tree's and is not refused; it is
    the marking machinery's to judge (the config is marked repository-written),
    not this gate's.
    """
    from automated_security_helper.config.sandbox_grants import is_within

    if os.path.isabs(config):
        named = Path(config)
    else:
        named = Path(os.getcwd()) / config
    trees = _scanned_tree_roots(Path(source_dir))
    # A relative name is also walked from the directory ``$PWD`` names when that
    # is the working directory under another spelling: a link the shell stands
    # below can sit in the scanned tree where the physical directory does not.
    # Either spelling being the tree's makes the name the tree's.
    spellings = [named]
    logical = _name_from_the_logical_directory(config)
    if logical is not None:
        spellings.append(logical)
    named_in_tree = [
        spelling for spelling in spellings if _named_in_a_scanned_tree(spelling, trees)
    ]
    if not named_in_tree:
        return
    named = named_in_tree[0]
    try:
        resolved = _real_path(config)
    except (OSError, ValueError):
        # A link on the name the host cannot read leaves the real path
        # unknowable (a platform can also raise ValueError for an entry it
        # reports as a link but cannot read as one), and nothing unprovable is
        # mounted. The name is the tree's, so the refusal says the link could
        # not be read, not that the name lands outside.
        raise _unresolvable_name(named, Path(config), _UNREADABLE_LINK) from None
    if any(is_within(resolved, tree) for tree in trees):
        return
    # Raw values: the message is shown once by whichever sink prints it (the
    # handlers one-pass it with shown_on_one_line, or print it as Text), and it
    # travels raw in a refusal result's stderr, so nothing shows it twice.
    raise ContainerInputError(
        f"The {label} '{config}' is inside the scanned tree but is "
        f"a link, or is reached through one, to '{resolved}', "
        "which is outside it. ASH does not "
        "mount a file the repository being scanned points it at. Name the file "
        "itself, outside the repository, or one inside it."
    )


def _refuse_absolute_extends(config: str) -> None:
    """Refuse a config whose ``extends`` chain names a base by absolute path.

    The chain is mounted at its place relative to the config, so a relative base
    resolves inside the container as on the host. An absolute one names a host
    path, which inside the container is missing or is some other file at the same
    path in the image. Walked from the config without the confinement checks, which
    the scan applies itself; a file that cannot be read ends the walk there, and the
    scan inside reports it.
    """
    from automated_security_helper.config.config_sources import EXTENDS_KEY
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    def real_path_of(file: Path, ref: str, in_file: str) -> Path:
        # A NUL in an entry cannot name a file on any host, and os.path.realpath
        # raises ValueError for it; refused as the chain's other unusable
        # entries are, instead of escaping the host's checks uncaught.
        try:
            return _real_path(file.parent / ref)
        except ValueError:
            raise ContainerInputError(
                f"'{EXTENDS_KEY}: {ref!r}' in {in_file} holds a NUL character, "
                "which cannot name a file. Remove it from the entry."
            ) from None

    start = _real_path(config)
    # The entries of each file, read once: a file that cannot be read maps to
    # None and ends the walk there.
    entries: Dict[Path, List[Tuple[str, str, bool]] | None] = {}
    # A first pass finds every file reached through an entry that reads the
    # environment, by any route, before the second pass names a file or
    # refuses a chain; so a name does not depend on which route is walked
    # first.
    hidden_files: Set[Path] = set()
    reached: Set[Tuple[Path, bool]] = set()
    walk = [(start, False)]
    while walk:
        current, hidden = walk.pop()
        if (current, hidden) in reached:
            continue
        reached.add((current, hidden))
        if hidden:
            hidden_files.add(current)
        if current not in entries:
            try:
                entries[current] = _extends_refs_shown(current, shown=str(current))
            except Exception:  # noqa: BLE001 - the scan inside reports why it cannot be read
                entries[current] = None
        for ref, _, env_read in entries[current] or ():
            if Path(ref).is_absolute() or Path(ref).drive:
                continue
            in_file = (
                ENVIRONMENT_VALUE_SHOWN
                if hidden
                else (str(config) if current == start else str(current))
            )
            walk.append((real_path_of(current, ref, in_file), hidden or env_read))

    def shown(file: Path) -> str:
        if file in hidden_files:
            return ENVIRONMENT_VALUE_SHOWN
        return str(config) if file == start else str(file)

    pending = [start]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for ref, written, _ in entries.get(current) or ():
            if Path(ref).is_absolute() or Path(ref).drive:
                raise ContainerInputError(
                    f"'{EXTENDS_KEY}: {written}' in {shown(current)} names a base "
                    "by absolute path, which does not name the same file inside "
                    "the container: the config and the files it extends are "
                    "mounted at their place relative to the config. Write the "
                    "base relative to the file that extends it."
                )
            pending.append(real_path_of(current, ref, shown(current)))


def _refuse_output_over_the_source(
    source_dir: Path | str, output_dir: Path | str
) -> None:
    """Refuse an output directory that is the source directory or above it.

    The source is mounted read-only at ``/src`` and the output read-write at
    ``/out``; an output directory that holds the source tree would make that tree
    writable through ``/out``. Compared by real path, so a link to the source
    counts. One inside the source, the default ``.ash/ash_output``, or outside it
    is fine, and so is an empty one, which the run puts at ``<source>/ash_output``.
    """
    if not str(output_dir):
        return
    source = Path(source_dir).resolve()
    output = Path(output_dir).resolve()
    if (
        source == output
        or source.is_relative_to(output)
        or _is_at_or_above(output_dir, source_dir)
    ):
        raise ContainerInputError(
            f"The output directory {output} is the source directory {source} or a "
            "directory above it. Container mode mounts the output read-write at "
            "/out and the source read-only at /src, so the source would be "
            "writable through /out. Use an output directory inside the source "
            "(the default .ash/ash_output) or outside it, not above it."
        )


def _is_at_or_above(ancestor: Path | str, path: Path | str) -> bool:
    """Whether ``ancestor`` is ``path`` or a directory above it, by identity.

    The directories are compared by device and inode (``os.path.samestat``), not
    by name: a bind mount, or another spelling of the case on a case-insensitive
    volume, names the same directory under a path the real-path comparison does
    not match. ``path`` is walked as given, then as its real path and that path's
    parents. A path that cannot be looked at matches nothing, and so does one
    whose volume reports no inode (``st_ino`` 0: some SMB and FUSE mounts, some
    Windows drives), where every directory on the device would otherwise compare
    equal: the real-path comparison beside this one still decides what it can.
    """
    try:
        wanted = os.stat(ancestor)
    except OSError:
        return False
    if wanted.st_ino == 0:
        return False
    real = Path(os.path.realpath(path))
    for candidate in (Path(path), real, *real.parents):
        try:
            status = os.stat(candidate)
        except OSError:
            continue
        if status.st_ino != 0 and os.path.samestat(status, wanted):
            return True
    return False


def _refuse_linked_output_dir(
    source_dir: Path | str | None, output_dir: Path | str | None
) -> None:
    """Refuse an output directory that is a symlink or is reached through one.

    The output is mounted read-write at ``/out``, so the scan inside the container
    writes wherever it leads, and a link the scanned repository commits (``.ash ->
    /some/host/dir``) would choose that directory. The rule is the one a sandboxed
    local scan applies, :func:`~automated_security_helper.utils.sandbox.policy.
    refuse_symlinked_output_dir`: the output directory itself when it is a symlink,
    wherever it is, and any symlink from below the source directory down to it.
    The source counts under the name it was given and under its real path, so an
    output spelled through either is examined; links at or above the source are
    the operator's own spelling and are not. Checked on the path as given, before
    it is created or resolved, because creating ``.ash/ash_output`` through a
    linked ``.ash`` already writes where the link points. An empty output
    directory is the one the run makes, ``<source>/ash_output``.

    Raises ContainerOutputLinkRefused, whose ``found`` describes the link as
    linked_output_component does, the description refuse_symlinked_output_dir
    reports too.
    """
    from automated_security_helper.utils.output_dir_links import (
        linked_output_component,
    )

    source = Path(source_dir) if source_dir else Path.cwd()
    output = (
        Path(output_dir)
        if output_dir is not None and str(output_dir)
        else source / "ash_output"
    )
    for named in (source, source.resolve()):
        found = linked_output_component(named, output)
        if found is not None:
            raise ContainerOutputLinkRefused(
                found,
                f"Refusing the output directory {output.as_posix()}: {found}, so "
                "mounting the output directory would expose wherever it points. "
                "Container mode mounts the output directory read-write at /out, so "
                "the scan inside the container would write through the link. Use a "
                "directory that is not a symlink and is not reached through one "
                "below the source directory.",
            )


def _refuse_unusable_output_dir(
    source_dir: Path | str | None, output_dir: Path | str | None
) -> None:
    """The checks on the directory mounted read-write at ``/out``.

    It must not hold the source tree (:func:`_refuse_output_over_the_source`) and
    must not be, or be reached through, a symlink (:func:`_refuse_linked_output_dir`).
    ``./ash`` and ``Invoke-ASH`` apply the same two, in this order.
    """
    _refuse_output_over_the_source(source_dir or Path.cwd(), output_dir or "")
    _refuse_linked_output_dir(source_dir, output_dir)


def container_output_dir_refusal(
    source_dir: Path | str | None, output_dir: Path | str | None
) -> ContainerOutputLinkRefused | None:
    """The refusal of the output directory for a container scan, or None.

    Only the link rule (:func:`_refuse_linked_output_dir`), which ``run_ash_scan``
    checks before its logger opens ``ash.log`` in the output directory, with or
    without ``--no-run``; the full set is checked with the other inputs by
    :func:`container_input_refusal`. The refusal's message is the reason, and its
    ``found`` names the link.
    """
    try:
        _refuse_linked_output_dir(source_dir, output_dir)
    except ContainerOutputLinkRefused as e:
        return e
    return None


_CHAIN_FILE_READS: contextvars.ContextVar[
    Dict[Path, Tuple[List[Tuple[str, str, bool]], List[str]]] | None
] = contextvars.ContextVar("ash_chain_file_reads", default=None)


def _reading_chain_files_once(function):
    """Decorate *function* so that, while it runs, each config file's
    ``extends`` entries (:func:`_extends_refs_shown`) are read once per path.

    The chain is walked by several checks on the way to a run, and each walk
    asks for the same files. The entries live on the call's
    :class:`OperatorConfigReads` when the decorated function was given one, so
    every check that shares the scan's record sees the same answer across
    calls, for the record's own lifetime (one phase); a call with no record
    keeps a store of its own and nothing outlives it. Nested calls share the
    outermost call's store either way.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        if _CHAIN_FILE_READS.get() is not None:
            return function(*args, **kwargs)
        reads = kwargs.get("reads")
        if reads is None:
            for value in args:
                if isinstance(value, OperatorConfigReads):
                    reads = value
                    break
        store = reads.extends_entries if reads is not None else {}
        token = _CHAIN_FILE_READS.set(store)
        try:
            return function(*args, **kwargs)
        finally:
            _CHAIN_FILE_READS.reset(token)

    return wrapper


def _environment_spelled_a_key(resolved_data: Any, literal_data: Any) -> bool:
    """Whether the environment spelled the ``extends`` key of the document.

    True when a top-level key written as a reference (a plain ``${VAR}`` or a
    tagged one) resolves to ``extends`` and is the entry the loader keeps for
    that name: a written ``extends`` key after it wins instead, and a reference
    key that resolves to any other name leaves the written key alone. Each
    reference key is resolved on its own. A format that never interpolates
    (JSON) resolves to the same keys, so a reference-looking key there is only
    text.
    """
    from automated_security_helper.config.ash_config import (
        ENV_REFERENCE_PATTERN,
        config_env_var_is_interpolatable,
        resolve_env_references,
    )
    from automated_security_helper.config.config_sources import (
        EXTENDS_KEY,
        TagWrittenReference,
    )
    from automated_security_helper.config.environment_record import (
        written_without_tag,
    )

    if not isinstance(resolved_data, dict) or not isinstance(literal_data, dict):
        return False
    if set(resolved_data) == set(literal_data) or EXTENDS_KEY not in resolved_data:
        return False
    # The loader builds a mapping in the order the file writes it, so the last
    # key that comes to ``extends`` holds the entry.
    spelled_last = False
    for key in literal_data:
        if not isinstance(key, str):
            continue
        if key == EXTENDS_KEY and not isinstance(key, TagWrittenReference):
            spelled_last = False
            continue
        if not (
            isinstance(key, TagWrittenReference) or ENV_REFERENCE_PATTERN.match(key)
        ):
            continue
        written = written_without_tag(key)
        match = ENV_REFERENCE_PATTERN.match(written)
        if match is None or not config_env_var_is_interpolatable(match.group(1)):
            continue
        try:
            resolved_key = resolve_env_references(written)
        except Exception:  # noqa: BLE001 - a key that does not resolve names nothing
            continue
        if resolved_key is not None and str(resolved_key) == EXTENDS_KEY:
            spelled_last = True
    return spelled_last


def _extends_refs_shown(
    path: Path, shown: str | None = None
) -> List[Tuple[str, str, bool]]:
    """Each ``extends`` entry of *path*: resolved, as written, and whether it
    reads the environment.

    :func:`_extends_read` also names the variables of an entry the resolution
    dropped.
    """
    return _extends_read(path, shown)[0]


def _extends_read(
    path: Path, shown: str | None = None
) -> Tuple[List[Tuple[str, str, bool]], List[str]]:
    """The ``extends`` entries of *path* as :func:`_extends_refs_shown` lists
    them, and the variables read by an entry the resolution dropped or a key
    the environment spelled as ``extends`` replaced.

    The one text is parsed both ways and the stock reader is the authority
    for what the chain holds: ``parse_config_text`` gives the values the
    scan inside will follow (JSON never interpolates, a quoted YAML scalar
    stays literal, a tagged entry resolves), and the literal parse gives the
    written form a message may quote, because an entry that reads the
    environment resolves to a string holding the variable's value. The host
    follows the stock reader's count: an entry the resolution dropped (a
    reference-only scalar whose variable is empty resolves to no extends) is
    no extends here either, and an entry the resolution materialized (a key
    the environment spelled) is followed with no written form to quote, shown
    as a value. An entry the stock reader refuses (a blank in a list, a value
    that is not a path or a list of paths) refuses here the same way, instead
    of being dropped. *shown* is how a refusal names the file: the caller's
    shown name, ``ENVIRONMENT_VALUE_SHOWN`` for a file the environment chose,
    whose path holds the variable's value.
    """
    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN
    from automated_security_helper.config.config_sources import (
        EXTENDS_KEY,
        TagWrittenReference,
        _extends_refs,
        parse_config_text,
        parse_config_text_literally,
        read_config_text,
        refuse_environment_in_a_delivered_file,
    )
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
        written_without_tag,
    )

    reads = _CHAIN_FILE_READS.get()
    key = Path(os.path.abspath(path))
    if reads is not None and key in reads:
        kept_entries, kept_dropped = reads[key]
        return list(kept_entries), list(kept_dropped)
    text = read_config_text(path)
    refuse_environment_in_a_delivered_file(path, text)
    resolved_data = parse_config_text(path, text)
    resolved_refs = _extends_refs(
        resolved_data.get(EXTENDS_KEY) if isinstance(resolved_data, dict) else None,
        path,
        shown_file=shown,
        from_environment=shown == ENVIRONMENT_VALUE_SHOWN,
    )
    literal_data = parse_config_text_literally(
        path, text, keep_env_tags=True, mark_written_tags=True
    )
    literal_value = (
        literal_data.get(EXTENDS_KEY) if isinstance(literal_data, dict) else None
    )
    written_refs = (
        [literal_value] if isinstance(literal_value, str) else literal_value or []
    )
    entries: List[Tuple[str, str, bool]] = []
    dropped: List[str] = []
    if not resolved_refs:
        # A reference-only scalar whose variable is empty resolves to no
        # extends, so no entry follows it; the file still reads the variable,
        # and the scan inside reads it too.
        for literal in written_refs:
            match = ENV_REFERENCE_PATTERN.match(written_without_tag(str(literal)))
            if match is not None:
                dropped.append(match.group(1))
    spelled_a_key = _environment_spelled_a_key(resolved_data, literal_data)
    if spelled_a_key:
        # The loader keeps the last entry written as ``extends``, and the key
        # the environment spelled is that entry. The written entries are
        # replaced, but the file still read their variables.
        for literal in written_refs:
            match = ENV_REFERENCE_PATTERN.match(written_without_tag(str(literal)))
            if match is not None:
                dropped.append(match.group(1))
    if len(resolved_refs) != len(written_refs) or spelled_a_key:
        # The resolution changed the entry list's shape, so the written
        # spellings cannot be paired to the entries the scan inside will
        # follow. Those entries are followed all the same -- the stock reader
        # is the authority -- and each is shown as one the environment chose,
        # because the shape change is the resolution's own doing. Equal
        # counts do not prove the entries line up: a key the environment
        # spells as ``extends`` can replace the written key's list with one of
        # the same length, and pairing by position would then quote the
        # written key's entries for the other list's bases.
        entries = [(ref, ENVIRONMENT_VALUE_SHOWN, True) for ref in resolved_refs]
    else:
        for resolved, literal in zip(resolved_refs, written_refs):
            # The tag-keeping loader marks the "!ENV " it added itself; the
            # same bytes in a JSON or quoted entry are the file's own text,
            # quoted as written and reading nothing.
            text_form = str(literal)
            if isinstance(literal, TagWrittenReference):
                text_form = written_without_tag(text_form)
            written = text_form.strip()
            entries.append((resolved, written, resolved != written))
    if reads is not None:
        reads[key] = (entries, dropped)
    return list(entries), list(dropped)


def _chain_placements(
    resolved: Path, destination: str, mount_root: str
) -> List[Tuple[Path, str]]:
    """Each file of a config's chain, with the container path the scan there reads it at.

    The scan inside resolves a base from the extending file's own path in the
    container, which is the mounted path (a bind-mounted file is no link). So a
    base goes where the extending file names it, relative to that file's mount,
    while its content comes from where the host resolves the same entry: the
    real path of the extending file plus the entry, links followed. A base the
    host reaches through a link therefore still sits where the scan inside looks.

    Every container path has to stay under *mount_root*, where the scan inside
    confines the chain. The host confines it by real paths and the container path
    is the entry as written, so the two can disagree: an entry that leaves the
    config's directory and comes back by name, or a ``..`` after a link to a
    directory at another depth. Such a chain is refused with ContainerInputError
    naming the entry, before anything is mounted. So is a chain where two files
    would be mounted at one container path, or one file at a path another needs as
    a directory.
    """
    placements, _, _ = _chain_placements_shown(resolved, destination, mount_root)
    return placements


def _chain_placements_shown(
    resolved: Path, destination: str, mount_root: str
) -> Tuple[List[Tuple[Path, str]], dict, dict]:
    """:func:`_chain_placements`, plus how a message may name each file and
    each container path.

    The second value maps each host file of the chain to the name a refusal
    prints for it: its own path, or ``ENVIRONMENT_VALUE_SHOWN`` for a file
    reached through an entry that reads the environment, and for every file
    below one -- the naming :func:`_extends_refs_shown` gives entries, applied
    once here so every chain refusal (this walk's own, and the base-membership
    checks that consume the placements) names files one way, with no masking
    arm of its own. A container path derives from the entries as the chain
    resolves them, so one reached through such an entry holds the variable's
    value too and is shown the same way. The files and container paths reached
    through such an entry are found by a first pass over the whole chain, so a
    name does not depend on the order the walk visits the entries.

    The third value maps each container path of the chain to the name a
    refusal prints for it, by the same rule applied to the placement: one file
    placed at two container paths can have one reached through an entry that
    reads the environment and one not, so the path's name is the placement's,
    not the file's.
    """
    from automated_security_helper.config.config_sources import EXTENDS_KEY
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    root = mount_root.rstrip("/")
    entries: Dict[Path, List[Tuple[str, str, bool]] | None] = {}
    # A first pass finds every file and container path reached through an
    # entry that reads the environment, by any route, before the second pass
    # names anything or refuses a chain; so every refusal below prints final
    # names, whichever route the walk takes first. Any file reached through
    # an environment-reading entry is shown as the marker, a deliberate
    # fail-safe over-mask keyed on how the file is reached, not on what its
    # path contains, so this is never narrowed to a substring check.
    hidden_files: Set[Path] = set()
    hidden_inners: Set[str] = set()
    reached: Set[Tuple[Path, str, bool]] = set()
    walk = [(resolved, destination, False)]
    while walk:
        host_file, inner, hidden = walk.pop()
        if (host_file, inner, hidden) in reached:
            continue
        reached.add((host_file, inner, hidden))
        if hidden:
            hidden_files.add(host_file)
            hidden_inners.add(inner)
        # A path outside the mount root is refused by the second pass, and
        # the walk does not go past it.
        if not inner.startswith(root + "/"):
            continue
        if host_file not in entries:
            try:
                entries[host_file] = _extends_refs_shown(
                    host_file, shown=str(host_file)
                )
            except Exception:  # noqa: BLE001 - the second pass reads it again and refuses
                entries[host_file] = None
        for ref, _, env_read in entries[host_file] or ():
            walk.append(
                (
                    _real_path(host_file.parent / ref),
                    posixpath.normpath(posixpath.join(posixpath.dirname(inner), ref)),
                    hidden or env_read,
                )
            )

    placements: List[Tuple[Path, str]] = []
    placed: dict = {}
    shown: dict = {}
    inner_shown: dict = {}
    # (host file, its container path, the shown (extending file, entry as
    # written) that named it)
    pending: List[Tuple[Path, str, Tuple[str, str] | None]] = [
        (resolved, destination, None)
    ]
    while pending:
        host_file, inner, named_by = pending.pop()
        host_name = (
            ENVIRONMENT_VALUE_SHOWN if host_file in hidden_files else str(host_file)
        )
        inner_name = ENVIRONMENT_VALUE_SHOWN if inner in hidden_inners else inner
        if not inner.startswith(root + "/"):
            extending, ref = (
                named_by if named_by is not None else (host_name, inner_name)
            )
            raise ContainerInputError(
                f"'{EXTENDS_KEY}: {ref}' in {extending} names {host_name}, which "
                f"would be mounted at {inner_name}, outside {mount_root}: inside the "
                "container the entry is followed as written, from where the "
                "extending file is mounted. Name the base by a path below the "
                "config's own directory that does not go through a link to a "
                "directory at another depth."
            )
        if inner in placed:
            if placed[inner] != host_file:
                raise ContainerInputError(
                    "Two files of the config's extends chain, "
                    f"{shown[placed[inner]]} and {host_name}, would both be "
                    f"mounted at {inner_name}. Name each base by its own path."
                )
            continue
        placed[inner] = host_file
        shown[host_file] = host_name
        inner_shown[inner] = inner_name
        placements.append((host_file, inner))
        read = entries.get(host_file)
        if read is None:
            read = _extends_refs_shown(host_file, shown=host_name)
        for ref, written, _ in read:
            pending.append(
                (
                    _real_path(host_file.parent / ref),
                    posixpath.normpath(posixpath.join(posixpath.dirname(inner), ref)),
                    (host_name, written),
                )
            )
    # A file mounted at a path another file of the chain needs as a directory: the
    # runner cannot create both mounts.
    for inner, host_file in placed.items():
        parent = posixpath.dirname(inner)
        while parent != root and parent.startswith(root + "/"):
            if parent in placed:
                raise ContainerInputError(
                    f"{shown.get(placed[parent], str(placed[parent]))} would be "
                    f"mounted at {inner_shown.get(parent, parent)}, where "
                    f"{shown.get(host_file, str(host_file))} needs a directory to "
                    f"be mounted at {inner_shown.get(inner, inner)}. Name each "
                    "base by its own path."
                )
            parent = posixpath.dirname(parent)
    return placements, shown, inner_shown


class _ChainPlan(NamedTuple):
    """One plan per config chain: the placements the mounts are built from, and
    the resolved document behind them, so the marks judge exactly the files the
    scan inside will read (:func:`_config_marks`, :func:`_env_config_marks`,
    :func:`_another_checkout_marks`) instead of resolving the chain again and
    drifting from what was mounted.

    ``placements`` is empty for a file inside the source directory, which rides
    the ``/src`` mount and needs no mark. ``document`` is the document
    ``config_sources.resolve_config_document`` returned, or None when the chain
    was not followed or did not resolve and the file is placed alone.
    """

    placements: List[Tuple[Path, str]]
    document: Any


class OperatorConfigReads:
    """What one scan has read of the operator's config chain, kept for the scan.

    A container scan asks about the same config files from several places: the
    refusal before anything starts (run by the CLI, by the container mode and by
    ``run_ash_container``), the names of the variables the files read, the mounts
    and the marks. Within one phase each is asked once: the chain document is
    resolved once per distinct root, and every asker that goes through this
    record gets the same answer back. The ``extends`` entries the chain walks
    ride here too (``extends_entries``, filled through
    ``_reading_chain_files_once``), so the checks that share the record judge
    the same entries across calls. The judgment passes that deliberately keep
    their own reads still read the disk themselves.

    The decisions that depend on the host's environment and on discovery in
    the source directory are kept the same way: which file ``ASH_CONFIG``
    names (:meth:`host_ash_config`) and whether that file is the scan's
    ``--config`` (:meth:`env_config_is_the_scans_config`). They are taken at the
    first ask of the record, which is the refusal that runs ahead of the
    build. A run that builds starts a fresh record for its run phase, so the
    command it assembles mounts and names what the files hold after the build;
    a run that does not build keeps the one record, and its command mounts and
    names what that refusal judged.

    One instance belongs to one phase of one scan. A chain document and the
    mounts are keyed on real paths, since the walk and the mount pass read only
    where their inputs resolve; the variable names are keyed on what their
    computation reads, which includes the scanned trees a source directory's
    names reach. A scan asks for the names, and judges the marks, with the
    source directory as the operator named it in every phase, so a phase that
    reuses the record gets the answer the refusal computed; only the mounts
    take the resolved directory. The run phase of a scan that built an
    image starts a fresh record (see the run phase of ``run_ash_container``):
    the container reads the files when it starts, so the run's mounts, marks
    and variable names describe the files as they are after the build. A result
    is stored only when its computation returned, so a computation that raises
    is run again by the next asker and raises the same way it would without
    this class.
    """

    def __init__(self) -> None:
        self._documents: Dict[Tuple[str, str], Any] = {}
        self._host_files: Dict[
            Tuple[str, str, str, bool],
            Tuple[List[str], str, List[Path], _ChainPlan],
        ] = {}
        self._names: Dict[
            Tuple[str | None, str | None, str, Tuple[Path, ...]], List[str]
        ] = {}
        self._env_config: Tuple[str | None] | None = None
        self._env_config_named: Dict[Tuple[str, str], bool] = {}
        #: Each config file's ``extends`` entries, read once for the record's
        #: lifetime, with the variables an entry the resolution dropped read;
        #: written by :func:`_extends_read` through
        #: :func:`_reading_chain_files_once`.
        self.extends_entries: Dict[
            Path, Tuple[List[Tuple[str, str, bool]], List[str]]
        ] = {}

    def host_ash_config(self) -> str | None:
        """:func:`_host_ash_config`, answered on the first ask only."""
        if self._env_config is None:
            self._env_config = (_host_ash_config(),)
        return self._env_config[0]

    def env_config_is_the_scans_config(
        self, env_config: str | None, source_dir: Path | str
    ) -> bool:
        """:func:`_env_config_is_the_scans_config` for these arguments, answered
        on the first ask only: the rule stays that function's, evaluated once."""
        if not env_config:
            return False
        key = (env_config, str(_real_path(source_dir)))
        if key not in self._env_config_named:
            self._env_config_named[key] = _env_config_is_the_scans_config(
                env_config, Path(source_dir)
            )
        return self._env_config_named[key]

    def config_document(self, resolved: Path, confine_to: Path):
        """``config_sources.resolve_config_document`` of *resolved* confined to
        *confine_to*, walked once per distinct pair."""
        from automated_security_helper.config.config_sources import (
            resolve_config_document,
        )

        key = (str(resolved), str(confine_to))
        if key not in self._documents:
            self._documents[key] = resolve_config_document(
                resolved, confine_to=confine_to
            )
        return self._documents[key]

    def host_file(
        self, host_path: str, source_dir: Path, mount_root: str, *, follow_extends: bool
    ) -> Tuple[List[str], str, List[Path], _ChainPlan]:
        """:func:`_host_file_in_container` for these arguments, built once: the
        mounts and the :class:`_ChainPlan` the marks judge come from one pass.
        The mount and file lists and the plan's placements are handed out as
        copies, so no caller's change to them reaches a later asker. The plan's
        document is the record's shared one, which no consumer changes."""
        key = (
            str(_real_path(host_path)),
            str(_real_path(source_dir)),
            mount_root,
            follow_extends,
        )
        if key not in self._host_files:
            self._host_files[key] = _host_file_in_container(
                host_path,
                source_dir,
                mount_root,
                follow_extends=follow_extends,
                reads=self,
            )
        mounts, inner, files, plan = self._host_files[key]
        return (
            list(mounts),
            inner,
            list(files),
            plan._replace(placements=list(plan.placements)),
        )

    def environment_names(
        self, config: str | None, env_config: str | None, source_dir: Path | str
    ) -> List[str]:
        """:func:`operator_environment_names` for these roots, computed once per
        distinct (config, ASH_CONFIG file, source directory) as the computation
        reads them: the roots as named, and the source directory by where it
        resolves and by the scanned trees its names reach, which is what the
        computation judges a file against. Two spellings that reach different
        trees can judge one file differently, so each gets its own answer."""
        if not config and not env_config:
            # No root to read: the computation never looks at the source directory.
            return []
        try:
            key = (
                config,
                env_config,
                str(_real_path(source_dir)),
                tuple(_scanned_tree_roots(Path(source_dir))),
            )
        except (OSError, ValueError):
            # An input the key cannot be built from is run uncached, so the
            # computation reports it the way it would without this class.
            return _operator_environment_names(config, env_config, source_dir, self)
        if key not in self._names:
            self._names[key] = _operator_environment_names(
                config, env_config, source_dir, self
            )
        return list(self._names[key])


def _refuse_bases_inside_the_source(
    config: Path, bases: List[Tuple[Path, str]], source: Path, shown: dict | None = None
) -> None:
    """Refuse a chain kept outside the source directory that extends a file inside it.

    The files of a chain kept outside the source directory are mounted from under
    the outside config's own directory (``config_sources.default_confinement_root``).
    A base inside the source directory is refused, and with it the files that base
    extends: a chain is either read whole through ``/src``, with the config inside
    the source directory, or mounted whole from outside it.
    """
    from automated_security_helper.config.sandbox_grants import is_within

    names = shown or {}
    for base, _ in bases:
        if is_within(base, source):
            raise ContainerInputError(
                f"The config file {config} is outside the source directory {source}, "
                f"but its extends chain includes {names.get(base, str(base))}, "
                "which is inside it. ASH does "
                "not mount files a config of the repository being scanned chooses. "
                "Keep the chain outside the repository, or put the config inside the "
                "source directory, where its whole chain stays there too."
            )


def _refuse_repository_bases_reaching_out(
    placements: List[Tuple[Path, str]], source: Path, shown: dict | None = None
) -> None:
    """Refuse a chain where a file inside the scanned checkout extends one outside it.

    A file of the chain inside the scanned checkout (``_scanned_tree_roots``) may
    extend only files inside that checkout. Files outside it are mounted when a
    config outside the checkout names them. Files and bases are named as *shown*
    (:func:`_chain_placements_shown`) says, and a base whose own entry reads the
    environment, or whose extending file was reached through one, is named
    ``ENVIRONMENT_VALUE_SHOWN``: its path holds the variable's value.
    """
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )
    from automated_security_helper.config.sandbox_grants import is_within

    trees = _scanned_tree_roots(source)
    names = shown or {}

    def written_by_the_repository(path: Path) -> bool:
        return any(is_within(path, tree) for tree in trees)

    for file, _ in placements:
        if not written_by_the_repository(file):
            continue
        file_name = names.get(file, str(file))
        for ref, _, env_read in _extends_refs_shown(file, shown=file_name):
            base = _real_path(file.parent / ref)
            if not written_by_the_repository(base):
                base_name = (
                    ENVIRONMENT_VALUE_SHOWN
                    if env_read or file_name == ENVIRONMENT_VALUE_SHOWN
                    else str(base)
                )
                raise ContainerInputError(
                    f"{file_name} is in the repository being scanned and extends "
                    f"{base_name}, which is outside it. ASH does not mount files "
                    "a config of the repository being scanned chooses. Extend "
                    "that file from a config outside the repository instead."
                )


def _host_file_in_container(
    host_path: str,
    source_dir: Path,
    mount_root: str,
    *,
    follow_extends: bool,
    reads: OperatorConfigReads | None = None,
) -> Tuple[List[str], str, List[Path], _ChainPlan]:
    """The mounts that make a host config file readable in the container, its path
    there, the host files those mounts are of, and the plan behind them
    (:class:`_ChainPlan`), which the marks consume so they judge the mounted
    files themselves rather than resolve the chain a second time.

    A file inside the source directory is already under the ``/src`` mount, and
    so is every ``extends`` base it can name: a config inside the source
    directory is confined to it (``config_sources.default_confinement_root``).

    A file outside it is mounted read-only under *mount_root* at its path relative
    to its confinement root, and with *follow_extends* each file of its ``extends``
    chain is mounted where the extending file names it (:func:`_chain_placements`),
    so the bases resolve inside the container to the files the host reads. Only
    those files are mounted, not the directory they are in. A chain that does not
    resolve on the host mounts the file alone: the scan inside reaches the same
    error and reports it with its own exit code. A chain with a base inside the
    source directory, with a file of the scanned checkout that extends a file
    outside it, or with a file whose container path would be outside *mount_root*,
    is refused with ContainerInputError.

    The path is resolved first, so a symlink is judged, and mounted, by its target.
    With *reads*, the chain's document comes from the scan's one walk of it
    (:meth:`OperatorConfigReads.config_document`).
    """
    resolved = _real_path(host_path)
    source = _real_path(source_dir)
    if resolved.is_relative_to(source):
        return (
            [],
            f"/src/{resolved.relative_to(source).as_posix()}",
            [],
            _ChainPlan([], None),
        )

    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        resolve_config_document,
    )

    root = default_confinement_root(resolved, source)
    inner_config = f"{mount_root}/{resolved.relative_to(root).as_posix()}"
    placements = [(resolved, inner_config)]
    chain_shown: dict = {}
    chain_inner_shown: dict = {}
    document = None
    if follow_extends:
        try:
            # Validated as the scan will validate it (confinement, bounds, cycles)
            # before anything is placed.
            document = (
                resolve_config_document(resolved, confine_to=root)
                if reads is None
                else reads.config_document(resolved, root)
            )
            placements, chain_shown, chain_inner_shown = _chain_placements_shown(
                resolved, inner_config, mount_root
            )
            _refuse_bases_inside_the_source(
                resolved, placements[1:], source, chain_shown
            )
            _refuse_repository_bases_reaching_out(placements, source, chain_shown)
        except ContainerInputError:
            raise
        except Exception as e:
            # See the docstring: the scan inside reports it. The error's text can
            # quote a chain entry resolved, which holds a value the chain read
            # from the environment, so it is rendered with every readable
            # variable's value hidden; the file itself is the one the caller
            # named, never a chain-chosen one.
            from automated_security_helper.utils.error_text import (
                text_without_values,
            )

            ASH_LOGGER.debug(
                f"Mounting {resolved} alone: its chain did not resolve: "
                f"{text_without_values(str(e), _readable_environment_values())}"
            )
            placements = [(resolved, inner_config)]
            chain_shown = {}
            chain_inner_shown = {}
            document = None

    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    mounts: List[str] = []
    for file, destination in placements:
        file_shown = chain_shown.get(file, str(file))
        _require_mountable(
            "config file",
            file,
            shown=None if file_shown == str(file) else file_shown,
        )
        # The file and its container path are judged separately: the container
        # path is the extends entry as written, which can hold the character
        # through a link's name while the file's own path does not, and one file
        # can be placed at two container paths with different origins. A path
        # reached through an env-reading entry holds the value.
        _require_mountable(
            "container path of a config file",
            destination,
            shown=(
                None
                if chain_inner_shown.get(destination, destination) == destination
                else ENVIRONMENT_VALUE_SHOWN
            ),
        )
        mounts.extend(
            ["--mount", f"type=bind,source={file},destination={destination},readonly"]
        )
    return (
        mounts,
        inner_config,
        list(dict.fromkeys(file for file, _ in placements)),
        _ChainPlan(placements, document),
    )


def _mount_env_config(
    env_config: str, source_dir: Path, reads: OperatorConfigReads | None = None
) -> Tuple[List[str], str, List[Path], _ChainPlan]:
    """The mounts, container path, host files and plan of ASH_CONFIG's file,
    checked as ``--config`` is: a file named inside the scanned tree that links
    out of it, and an absolute ``extends`` entry, are refused, and the chain is
    mounted by :func:`_host_file_in_container` under CONTAINER_ENV_CONFIG_ROOT."""
    _refuse_config_linked_out_of_the_tree(env_config, source_dir, "ASH_CONFIG file")
    _refuse_absolute_extends(env_config)
    if reads is None:
        reads = OperatorConfigReads()
    return reads.host_file(
        env_config, source_dir, CONTAINER_ENV_CONFIG_ROOT, follow_extends=True
    )


def _unreadable_config(config: str | None) -> str | None:
    """Why ``--config`` cannot be handed to the scan in the container, or None.

    The scan in the container reads the file through a mount, so the path has to
    name a file that exists on the host. One that does not -- or an empty value, or a
    directory -- is refused with exit 3, the code a local scan gives an unusable
    config, rather than mounted as nothing and scanned with the defaults.
    """
    if config is None:
        return None
    # _is_file: a path under an unsearchable directory is refused, not raised as
    # the PermissionError Path.is_file re-raises on Python 3.10 to 3.13.
    if not config or not _is_file(Path(config)):
        return (
            f"Config file not found: {config}. --config (or ASH_CONFIG) has to name "
            "an existing file: container mode mounts it read-only for the scan inside "
            "the container."
        )
    if not os.access(config, os.R_OK):
        # The runner mounts with its own rights, which can be wider than ASH's.
        return (
            f"Config file cannot be read: {config}. ASH does not hand the container "
            "runner a file it cannot read itself."
        )
    return None


def _invalid_revision_message(revision: str) -> str:
    return (
        f"Invalid ASH revision value: {revision!r}. Only alphanumeric characters, "
        "dots, hyphens, underscores, and forward slashes are allowed."
    )


def container_build_refusal(
    *,
    build: bool,
    build_target: BuildTarget | str | None,
    custom_containerfile: str | None,
    container_uid: str | None,
    container_gid: str | None,
    ash_revision_to_install: str | None,
    host_uid: int | str,
    host_gid: int | str,
) -> Tuple[int, str] | None:
    """Why the image cannot be built or run with these inputs: (exit code, message).

    A ``--container-uid`` or ``--container-gid`` that is not 0-9 digits (exit 3), an
    ``--ash-revision-to-install`` the build cannot take (exit 1), and, when building,
    ``--build-target non-root`` with a ``--custom-containerfile`` that has no such
    stage (exit 3, :func:`_custom_containerfile_stage_refusal`) or a ``non-root``
    stage with a UID or GID of 0 (exit 3, see
    :func:`_non_root_stage_uid_refusal`). ``run_ash_container`` checks these before
    anything else; ``run_ash_scan`` checks them before it clears the previous run's
    output, so a refused scan leaves that output as it was. None when the inputs
    can be used. The revision ASH derives from its own installation, when none is
    given, is not an input and is checked where ``run_ash_container`` resolves it.
    """
    for label, value in (("UID", container_uid), ("GID", container_gid)):
        # 0-9 only: str.isdigit also accepts digits such as "²" or "٠", which
        # neither the build nor int() reads as an ID.
        if value is not None and not _ASCII_DIGITS.fullmatch(value):
            return 3, f"Container {label} must be a numeric value"

    if ash_revision_to_install is not None and ash_revision_to_install != "LOCAL":
        if not _validate_ash_revision(ash_revision_to_install):
            return 1, _invalid_revision_message(ash_revision_to_install)

    if build:
        custom_refusal = _custom_containerfile_stage_refusal(
            build_target, custom_containerfile
        )
        if custom_refusal is not None:
            return 3, custom_refusal
        refusal = _non_root_stage_uid_refusal(
            _resolve_build_target(build_target, custom_containerfile),
            container_uid if container_uid is not None else str(host_uid),
            container_gid if container_gid is not None else str(host_gid),
        )
        if refusal is not None:
            return 3, refusal
    return None


def _host_ash_config() -> str | None:
    """The file the host's ``ASH_CONFIG`` names, or None when it names none.

    A local scan reads that file first, whatever else names a config
    (``default_config.get_default_config``): it is the base the settings a
    repository-written config may not choose come from (and, in a local scan, the
    sandbox mode's floor; the scan inside a container runs with ``sandbox.mode=off``
    as its last override). The scan inside the container sees neither the host's
    environment nor the file, so container mode mounts the file's chain under
    CONTAINER_ENV_CONFIG_ROOT and passes its path there with
    ASH_CONFIG_FROM_HOST_FLAG. A value ``default_config._ash_config_file`` refuses
    (only whitespace, or a path that does not exist) is refused here with its
    message.
    """
    from automated_security_helper.config.default_config import _ash_config_file
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    try:
        path = _ash_config_file()
    except ASHConfigValidationError as e:
        raise ContainerInputError(str(e)) from e
    return None if path is None else os.environ["ASH_CONFIG"]


def _env_config_is_the_scans_config(
    env_config: str | None,
    source_dir: Path,
    permit: Callable[[Path], bool] | None = None,
) -> bool:
    """Whether the file ``ASH_CONFIG`` names is the scan's ``--config``.

    The one rule: discovery first, the environment's file only when discovery
    finds nothing in *source_dir*. run_ash_scan's fallback and this launcher's
    carry both read it, and the question it asks is the one the parse check asks
    (``run_ash_scan._container_config_to_parse``): ``find_config_file`` of the
    source directory, so the file the host parse-checks and the file the scan
    inside discovers are one answer, and neither can be told apart from the
    environment's file by a different definition of "discoverable". It applies
    to a scan of one directory. A caller that names the config itself never
    reaches it, since an option wins over discovery, and a workspace scan does not
    ask it (see ``_assemble_run_command``): with no ``--config`` it names the file
    whatever discovery finds, and refuses a file in the workspace's own checkout
    (:func:`_refuse_repository_config_in_a_workspace`). With no ``ASH_CONFIG``
    value the answer is False without a discovery read. A discovery error also answers
    False, and is left to the scan, which reports it. ``permit`` is the scan's
    ``config_base_gate`` where the caller holds one: discovery checks each source
    against it before opening anything, as the scan's own discovery does.
    """
    if not env_config:
        return False
    from automated_security_helper.config.resolve_config import find_config_file

    try:
        return find_config_file(Path(source_dir), permit=permit) is None
    except Exception:
        return False


def _config_marks(
    config: str, source_dir: Path, plan: _ChainPlan
) -> Tuple[bool, List[str]]:
    """Which mounted config files a local scan of *source_dir* would count as
    repository-written: (the --config itself, the container paths of the files it
    extends that are).

    The same rule a local scan's membership judgments apply
    (:func:`_repository_written`, over ``sandbox_grants.files_inside``), to each
    file by its resolved path and by the names that reached it (the --config as
    the operator named it, and each base as its extends entry spells it): a file
    inside the scanned trees, or reached through a link inside them. The files
    are mounted at
    /ash-config, outside the scan's own tree inside the container, so the host
    decides and tells it: the whole chain with CONFIG_FROM_SCANNED_REPOSITORY_FLAG
    when the --config is repository-written, else each base that is with
    CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG, so the --config keeps the sandbox
    settings it writes itself, as it does on the host. A config inside the source
    directory is read through /src and needs neither (an empty *plan*).

    *plan* is the one :func:`_host_file_in_container` built the mounts from, so
    the files judged here are exactly the files placed there: the chain is never
    resolved a second time. A judgment that fails after the chain was prepared
    for mounting refuses the scan with ContainerInputError, rather than hand the
    scan inside a mounted checkout file without its mark.
    """
    source = Path(source_dir)
    if not plan.placements:
        return False, []
    try:
        resolved = plan.placements[0][0]
        if _repository_written(resolved, source) or _repository_written(
            Path(config), source
        ):
            # The chain mark makes the whole chain the repository's, and each BASE
            # is listed on its own as well, so a membership test given one mounted
            # base alone still reads it as marked (path_trust.in_scanned_tree over
            # sandbox_grants.files_inside). The root itself is not listed twice:
            # the chain mark already names it, and a single-file chain then
            # carries the chain mark alone, as before.
            return True, sorted({inner for _file, inner in plan.placements[1:]})
        names: dict = {}
        if plan.document is not None:
            for file, name in zip(plan.document.chain, plan.document.named):
                names.setdefault(Path(file), []).append(Path(name))
        marked = [
            inner
            for file, inner in plan.placements[1:]
            if _repository_written(file, source)
            or any(_repository_written(name, source) for name in names.get(file, []))
        ]
        return False, sorted(set(marked))
    except ContainerInputError:
        raise
    except Exception as e:
        raise ContainerInputError(
            f"The config file '{config}' was prepared for mounting, but which of "
            f"its files the scanned repository wrote could not be judged: {e}. "
            "Container mode refuses the scan rather than hand the scan inside a "
            "mounted file without the mark a local scan's judgment would give it."
        ) from e


def _refuse_repository_written_policy(
    workspace_config: str, source_dir: Path, plan: _ChainPlan
) -> None:
    """Refuse a mounted workspace policy the scanned repository wrote.

    A mounted config chain carries the repository-written judgment into the
    container (:func:`_config_marks`, :func:`_env_config_marks`); the
    workspace policy has no mark the scan inside reads, so a policy that
    judgment would mark is refused instead of mounted with no signal. The
    judgment is the same one, over the resolved file and the name the
    operator gave (:func:`_repository_written`). A policy inside the source
    directory rides the source mount and is judged inside (an empty *plan*).
    """
    source = Path(source_dir)
    if not plan.placements:
        return
    try:
        resolved = plan.placements[0][0]
        written = _repository_written(resolved, source) or _repository_written(
            Path(workspace_config), source
        )
    except ContainerInputError:
        raise
    except Exception as e:
        raise ContainerInputError(
            f"The workspace policy '{workspace_config}' was prepared for "
            f"mounting, but whether the scanned repository wrote it could not "
            f"be judged: {e}. Container mode refuses the scan rather than "
            "apply a policy without that judgment."
        ) from e
    if written:
        raise ContainerInputError(
            f"The workspace policy '{workspace_config}' is written by the "
            "repository being scanned. A mounted config chain carries that "
            "judgment into the container as a mark; the workspace policy has "
            "no mark, so ASH does not apply a policy the scanned repository "
            "wrote. Keep the policy outside the repository."
        )


def _env_config_marks(env_config: str, source_dir: Path, plan: _ChainPlan) -> List[str]:
    """The container paths of the files of ASH_CONFIG's chain a local scan of
    *source_dir* would count as repository-written.

    Each file is judged on its own, as a local scan judges the chain of the
    file ``ASH_CONFIG`` names: by its resolved path and by the names that
    reached it, the value of ``ASH_CONFIG`` for the root and each base's
    extends entry. The scan inside is told with
    CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG, once per file. A file inside the
    source directory is read through /src, where the scan inside judges it, and
    needs no mark (an empty *plan*).

    *plan* is the one :func:`_mount_env_config` built the mounts from, so the
    files judged here are exactly the files placed there: the chain is never
    resolved a second time. A judgment that fails after the chain was prepared
    for mounting refuses the scan with ContainerInputError, rather than hand the
    scan inside a mounted checkout file without its mark.
    """
    source = Path(source_dir)
    if not plan.placements:
        return []
    try:
        resolved = plan.placements[0][0]
        names: dict = {resolved: [Path(env_config)]}
        if plan.document is not None:
            for file, name in zip(plan.document.chain, plan.document.named):
                names.setdefault(Path(file), []).append(Path(name))
        marked = [
            container_path
            for file, container_path in plan.placements
            if _repository_written(file, source)
            or any(_repository_written(name, source) for name in names.get(file, []))
        ]
        return sorted(set(marked))
    except ContainerInputError:
        raise
    except Exception as e:
        raise ContainerInputError(
            f"The ASH_CONFIG file '{env_config}' was prepared for mounting, but "
            f"which of its files the scanned repository wrote could not be judged: "
            f"{e}. Container mode refuses the scan rather than hand the scan inside "
            "a mounted file without the mark a local scan's judgment would give it."
        ) from e


def _another_checkout_marks(
    root: str,
    plan: _ChainPlan,
    scanned_tree_marked: Sequence[str] = (),
) -> List[str]:
    """The container paths of the files of the chain rooted at *root* that a local
    scan counts as inside a git checkout other than the scanned tree.

    The host's second answer for a chain file. A file in the scanned trees is
    the repository's (:func:`_config_marks`, :func:`_env_config_marks`); one in
    some other checkout, such as an ops repository, is not a member of the tree
    but cannot grant either, and an ASH_CONFIG file there still sets what only
    restricts (``config/restrictions_kept``). The mounted copy is at
    ``/ash-config`` or ``/ash-env-config``, in no checkout inside the container,
    so the host tells the scan inside, one file at a time, with
    CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG. Only the class travels: the scan
    inside reads the mounted file itself for what it restricts, so no value of
    the file is in a mark and a mark cannot carry a grant.

    A file the judgment admitted only because the walk of the links in its name
    stopped before it could rule a checkout out is returned with the others: the
    limits are the same, and a mark only restricts. The host never gets there for
    a real layout. The scanned tree's judgment (:func:`_repository_written`) reads
    a name whose walk stopped as the scanned tree's, and a file it marked is left
    to that mark (*scanned_tree_marked*), so a stopped walk has no mark of its own.

    The judgment is the scan's own (``resolve_config._with_any_checkout_files``),
    run over each placed file by its resolved path and by the names that reached
    it: *root* as the operator gave it, and each ``extends`` entry as written.
    As for the scanned tree's marks (:func:`_repository_written`), *root* is also
    judged as ``$PWD`` spells it; that spelling can only add a mark, and a mark
    only restricts. A file in *scanned_tree_marked* is left to that mark. *plan*
    is the one the mounts were built from, so the files judged are exactly the
    files placed there. A judgment that fails after the chain was prepared for
    mounting refuses the scan with ContainerInputError, rather than hand the scan
    inside a mounted file without its mark.
    """
    if not plan.placements:
        return []
    try:
        from automated_security_helper.config.resolve_config import (
            _with_any_checkout_files,
        )

        names = [Path(root)]
        logical = _name_from_the_logical_directory(root)
        if logical is not None:
            names.append(logical)
        if plan.document is not None:
            names.extend(Path(name) for name in plan.document.named)
        found = set(
            _with_any_checkout_files(
                [],
                [Path(file) for file, _inner in plan.placements],
                names,
            )
        )
        return sorted(
            {
                inner
                for file, inner in plan.placements
                if Path(file) in found and inner not in scanned_tree_marked
            }
        )
    except Exception as e:
        raise ContainerInputError(
            f"The config file '{root}' was prepared for mounting, but which of its "
            f"files a git checkout other than the scanned one holds could not be "
            f"judged: {e}. Container mode refuses the scan rather than hand the "
            "scan inside a mounted file without the mark a local scan's judgment "
            "would give it."
        ) from e


#: Names the container image defines for the tools inside it (home directory,
#: search path, temporary directories, user, shell, locale, library loading). A
#: host value for one is wrong there by construction, so a config file that reads
#: one refuses the scan with exit 3, the same way a name in
#: ``CONTAINER_ENV_NOT_PASSED`` does. Passing it would override the image's own
#: value for every scanner inside; silently dropping it would run the config with
#: values its reads never see; refusing names the conflict.
CONTAINER_IMAGE_OWNED_ENV = frozenset(
    {
        "HOME",
        "PATH",
        "PYTHONPATH",
        "TMPDIR",
        "TMP",
        "TEMP",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
    }
)

#: Names a container scan does not pass into the container, though an operator's
#: config file may read one (``operator_environment_names``). The run command sets
#: the first group itself. ASH reads the rest as its own settings, and container
#: mode hands each of those in another way (ASH_CONFIG's file is mounted and named
#: with ASH_CONFIG_FROM_HOST_FLAG; the shard, the scanners, the plugin modules and
#: the workspace are flags), or the setting is the host's alone: a host path, how
#: the host builds the image, or how the host runs ASH. A config file that reads
#: one refuses the scan with exit 3, rather than run with a value the scan inside
#: would not read.
CONTAINER_ENV_NOT_PASSED = frozenset(
    {
        # Set by the run command.
        "ASH_ACTUAL_SOURCE_DIR",
        "ASH_ACTUAL_OUTPUT_DIR",
        "ASH_DEBUG",
        "ASH_OFFLINE",
        "ASH_SCAN_SOURCE",
        OUTER_RUN_ID_ENV,
        "COLUMNS",
        "LINES",
        # ASH's own settings.
        "ASH_CONFIG",
        "ASH_SHARD_INDEX",
        "ASH_SHARD_COUNT",
        "ASH_SCANNERS",
        "ASH_EXCLUDED_SCANNERS",
        "ASH_PLUGIN_MODULES",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_MODE",
        "ASH_VERBOSE",
        "ASH_CHANGED_FILES_ONLY",
        "ASH_BASE_REF",
        "ASH_BIN_PATH",
        "ASH_IN_CONTAINER",
        "ASH_IN_NIX",
        "ASH_STATE_DIR",
        "ASH_NIX_FLAKE_REF",
        "ASH_IMAGE_NAME",
        "ASH_BASE_IMAGE_OVERRIDE",
        "ASH_BASE_OCI_LAYOUT",
        "ASH_GHA_BUILD_CACHE_EXPORT",
        "ASH_DISABLE_GHA_BUILD_CACHE",
        "ASH_INSTALLED_REVISION",
        "ASH_TOOL_DOWNLOAD_CACHE",
        "ASH_THIRD_PARTY_DIR",
        "ASH_PINS_DIR",
        "ASH_LOG_TO_STDERR",
        # The host's alone too: an opt-in for tools found inside the scanned tree
        # (utils/subprocess_utils.py), the host's rules bundle root
        # (utils/rules_bundles.py), the `ash dependencies` unknown-tools setting
        # (cli/dependencies.py), the detect-secrets worker's own switch
        # (utils/detect_secrets_worker.py), the MCP server's git host allowlist
        # (cli/mcp/source_delivery.py), and a value the image's own build sets
        # (utils/content_databases.py).
        "ASH_ALLOW_IN_TREE_TOOLS",
        "ASH_CFN_GUARD_RULES_DIR",
        "ASH_DEPENDENCIES_UNKNOWN_TOOLS",
        "ASH_DETECT_SECRETS_REFUSE_HTTP",
        "ASH_MCP_GIT_ALLOWED_HOSTS",
        "ASH_OFFLINE_AT_BUILD_TIME",
        # Named through the helper module's constant: utils/log.py is the one
        # reader of the variable, and this list only names it.
        SHOW_LOCALS_VARIABLE,
        "ASH_MCP_ALLOWED_ROOTS",
        "ASH_MCP_ALLOWED_CONFIG_ROOTS",
        "ASH_MCP_WORKSPACE_ROOT",
        "ASH_MCP_TRANSPORT",
        "ASH_LOG_LEVEL",
        "ASH_DEFAULT_SEVERITY_LEVEL",
        "ASH_PROJECT_NAME",
        "ASH_DOWNLOAD_MAX_ATTEMPTS",
        "ASH_DOWNLOAD_RETRY_DELAY",
        # Read by reporters and model plugins inside the container as their
        # own settings, so a value passed for a config's reference would also
        # set them there.
        "ASH_BEDROCK_MODEL_ID",
        "ASH_BEDROCK_MAX_TOKENS",
        "ASH_BEDROCK_TEMPERATURE",
        "ASH_CLOUDWATCH_LOG_GROUP_NAME",
        "ASH_S3_BUCKET_NAME",
    }
)


def _operator_files_and_references(
    root: str,
    source_dir: Path,
    chain_follows_root: bool,
    reads: OperatorConfigReads | None = None,
):
    """The operator-written files of the config chain rooted at *root*, with the
    chain's resolved document: (files, document), or (set(), None) for a chain
    container mode does not mount.

    A file counts as the scanned repository's by the rule a local scan applies
    to its config files (:func:`_repository_written`, as ``_config_marks`` and
    ``_env_config_marks`` judge them): a file inside the scanned trees, by its
    resolved path or by a name that reached it. With
    *chain_follows_root*, a root that counts makes its whole chain count, as for
    a ``--config``; otherwise each file is judged alone, as for ``ASH_CONFIG``'s.
    """
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        resolve_config_document,
    )

    source = Path(source_dir)
    resolved = _real_path(root)
    if resolved.is_relative_to(_real_path(source)):
        return set(), None
    if chain_follows_root and (
        _repository_written(resolved, source) or _repository_written(Path(root), source)
    ):
        return set(), None
    confine_to = default_confinement_root(resolved, _real_path(source))
    document = (
        resolve_config_document(resolved, confine_to=confine_to)
        if reads is None
        else reads.config_document(resolved, confine_to)
    )
    names: dict = {resolved: [Path(root)]}
    for file, name in zip(document.chain, document.named):
        names.setdefault(Path(file), []).append(Path(name))
    files = {
        Path(file)
        for file in document.chain
        if not _repository_written(Path(file), source)
        and not any(
            _repository_written(name, source) for name in names.get(Path(file), [])
        )
    }
    return files, document


def operator_environment_names(
    config: str | None,
    env_config: str | None,
    source_dir: Path | str,
    reads: OperatorConfigReads | None = None,
) -> List[str]:
    """The names :func:`_operator_environment_names` finds. With *reads*, the
    answer is the scan's one computation of it for these roots
    (:meth:`OperatorConfigReads.environment_names`)."""
    if reads is not None:
        return reads.environment_names(config, env_config, source_dir)
    return _operator_environment_names(config, env_config, source_dir, None)


def _operator_environment_names(
    config: str | None,
    env_config: str | None,
    source_dir: Path | str,
    reads: OperatorConfigReads | None,
) -> List[str]:
    """The environment variables the operator's own config files read, which the
    scan inside the container is given.

    The scan inside the container sees none of the host's environment, so a
    ``${VAR}`` it reads resolves to the default the file wrote, and the scan, and
    its exit code, would differ from a local scan's. The operator's files are the
    ``--config`` and the file ``ASH_CONFIG`` names, with the bases they extend,
    less any file a local scan counts as the scanned repository's -- inside a
    scanned tree by its resolved path or by the name that reached it, or marked
    repository-written (:func:`_operator_files_and_references`);
    ``--config-overrides`` read no variable. A variable a repository-written
    file reads is not passed: the scan inside reads that file as it would with
    no host environment, so no value the operator did not choose enters the
    container, where the scanners read the repository's content. Only references the loader resolves
    are found (``environment_record``'s rule, through the chain's own resolution),
    an ``extends`` entry's included, and only those names are set.

    Raises:
        ContainerInputError: A file that does not load, or one that reads a name in
            ``CONTAINER_ENV_NOT_PASSED``, naming the file, the variable and the
            field, never the value (exit 3).
    """
    import yaml

    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
        written_without_tag,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    # Each variable found, with the file that reads it as a refusal names it:
    # its own path, or ENVIRONMENT_VALUE_SHOWN for a file reached through an
    # entry that reads the environment (its path holds that variable's value).
    found: Dict[str, Tuple[str, str]] = {}
    roots = [(env_config, False), (config, True)]
    for root, chain_follows_root in roots:
        if not root:
            continue
        try:
            files, document = _operator_files_and_references(
                root, Path(source_dir), chain_follows_root, reads
            )
            env_reached = document.environment_paths if document is not None else ()

            def shown_file(file: Path, env_reached=env_reached) -> str:
                return (
                    ENVIRONMENT_VALUE_SHOWN
                    if Path(file) in env_reached
                    else file.as_posix()
                )

            if document is not None:
                # What each operator file's data read, at the place the file
                # wrote it. The whole chain's references are recorded on the
                # document; a repository-written file's are left out here, as
                # the scan inside reads that file with no host environment.
                for reference in document.environment_references:
                    if reference.origin is None:
                        continue
                    file = Path(reference.origin[0])
                    if file not in files:
                        continue
                    match = ENV_REFERENCE_PATTERN.match(
                        written_without_tag(reference.written)
                    )
                    if match is None:
                        continue
                    field = ".".join(str(step) for step in reference.origin[1])
                    found.setdefault(match.group(1), (shown_file(file), field))
            # An extends entry's reference names a base, so the document records
            # it apart from the data (environment_paths); the entry still has to
            # resolve inside the container to the base the host followed.
            for file in files:
                for ref in _extends_reference_names(file):
                    found.setdefault(ref, (shown_file(file), "extends"))
        except (ASHConfigValidationError, OSError, ValueError, yaml.YAMLError) as e:
            # Raw value, like the link refusal above: the sinks show it once.
            raise ContainerInputError(
                f"Could not read the variables {root} reads from "
                "the environment, so the container scan cannot be given them: "
                f"{_unloadable_config_detail(e, _files_reached_through_environment(root))}"
            ) from e
    for name, (file, field) in found.items():
        if name in CONTAINER_ENV_NOT_PASSED:
            where = f" for {field}" if field else ""
            raise ContainerInputError(
                f"{file} reads the environment variable {name}{where}, "
                "which a container scan does not pass into the container, because "
                "ASH sets it there or reads it as its own setting. Write the value "
                "in the file instead, or pass it with --config-overrides"
                + (f" '{field}=<value>'." if field else ".")
            )
        if name in CONTAINER_IMAGE_OWNED_ENV:
            where = f" for {field}" if field else ""
            raise ContainerInputError(
                f"{file} reads the environment variable {name}{where}, "
                "which a container scan does not pass into the container, because "
                "the image defines it for the tools inside. Write the value in the "
                "file instead, or pass it with --config-overrides"
                + (f" '{field}=<value>'." if field else ".")
            )
    return sorted(found)


def _extends_reference_names(file: Path) -> List[str]:
    """The environment variables *file*'s ``extends`` entries read.

    From the entries :func:`_extends_refs_shown` classifies, the one
    classification the chain walk and the refusals share: an entry reads the
    environment when the stock reader resolved it from a reference, so a
    JSON ``"${VAR}"``, a quoted YAML ``"${VAR}"`` and a JSON
    ``"!ENV ${VAR}"`` read nothing and name no variable. An entry the
    resolution reshaped (a key the environment spelled) has no written form
    to take a name from and names none here: the variable that spelled the
    key is recorded with the document's other references, which the caller
    reads first. A file that does not read is left to the chain's own
    resolution to report. A reference-only scalar whose variable is empty
    resolves to no entry, but the file reads the variable, so it is named.
    """
    from automated_security_helper.config.ash_config import ENV_REFERENCE_PATTERN

    try:
        entries, dropped = _extends_read(file)
    except Exception:  # noqa: BLE001 - the chain's own resolution reports it
        return []
    names: List[str] = list(dropped)
    for _, written, env_read in entries:
        if not env_read:
            continue
        match = ENV_REFERENCE_PATTERN.match(written)
        if match is not None:
            names.append(match.group(1))
    return names


def _files_reached_through_environment(root: str | Path) -> frozenset:
    """The files of the chain rooted at *root* whose path holds a value read from
    the environment: each base an ``extends`` entry that reads the environment
    names, and every base below one.

    The walk is :func:`_refuse_repository_bases_reaching_out`'s, over the
    entries :func:`_extends_refs_shown` classifies. A file
    that cannot be read ends the walk there: the refusal that follows names it.
    """
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    reached: set = set()
    seen: set = set()
    pending = [(_real_path(root), False)]
    while pending:
        current, hidden = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            refs = _extends_refs_shown(
                current, shown=ENVIRONMENT_VALUE_SHOWN if hidden else None
            )
        except Exception:  # noqa: BLE001 - the refusal reports why it cannot be read
            continue
        for ref, _, env_read in refs:
            child = _real_path(current.parent / ref)
            if hidden or env_read:
                reached.add(child)
            pending.append((child, hidden or env_read))
    return frozenset(reached)


def _unloadable_config_detail(
    error: BaseException, env_reached: frozenset = frozenset()
) -> str:
    """What is wrong with a config file that did not load, without its contents.

    A YAML error names the file the parser stopped in. When that file is one of
    *env_reached* (:func:`_files_reached_through_environment`), its path holds
    a value read from the environment, so it is named
    ``ENVIRONMENT_VALUE_SHOWN`` instead.

    A YAML error, the one raised or the one behind it (a base file's, for one), is
    shown by its file, the parser's problem, the error's type and its position: the
    parser's whole message also repeats the line it stopped at, values and all, when
    it has the text. The problem names what it found by kind, or by a character, an
    alias or a tag. A validation error is shown by each field and its problem,
    without the value the field was given (``errors(include_input=False)``), which
    can be a credential read from the environment. Any other error is ASH's own
    text, which names a value read from the environment by where it came from.
    """
    import pydantic
    import yaml

    seen = set()
    cause: BaseException | None = error
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, yaml.YAMLError):
            mark = getattr(cause, "problem_mark", None)
            where = (
                f" at line {mark.line + 1}, column {mark.column + 1}"
                if mark is not None
                else ""
            )
            name = getattr(mark, "name", None)
            in_file = ""
            if isinstance(name, str) and not name.startswith("<"):
                from automated_security_helper.config.environment_record import (
                    ENVIRONMENT_VALUE_SHOWN,
                )

                in_file = (
                    f"{ENVIRONMENT_VALUE_SHOWN}: "
                    if _real_path(name) in env_reached
                    else f"{name}: "
                )
            problem = getattr(cause, "problem", None)
            shown = problem if isinstance(problem, str) else "it does not parse"
            return f"{in_file}{shown} ({type(cause).__name__}{where})"
        if isinstance(cause, pydantic.ValidationError):
            return "; ".join(
                f"{'.'.join(str(step) for step in entry['loc']) or 'the file'}: "
                f"{entry['msg']}"
                for entry in cause.errors(include_input=False, include_url=False)
            )
        cause = cause.__cause__ or cause.__context__
    return str(error)


def _write_env_file(
    names: List[str],
    environ: Mapping[str, str],
    runner: str,
    source_dir: Path,
    output_dir: Path,
) -> Tuple[Path, Path]:
    """The env file a wrapped runner reads *names* from: (its directory, the file).

    Through ``OCI_RUNNER_WRAPPER`` (``sudo``, for one) the runner need not get this
    process's environment, so ``-e NAME`` could pass nothing. The values go in a
    file instead, which only this user can read: mode 0600, created exclusively,
    in a new mode 0700 directory outside the source and output directories. Only
    its path is on the command line. The caller removes the directory once the
    run ends, however it ends.

    The file is also put on the die-now cleanup record, before it is created, so a
    die-now ending that never reaches the caller's ``finally`` still removes it. A
    caller that takes the file owes both: remove the directory, then drop the
    record once the file is gone. :func:`_env_file` does both, and is the way to
    call this.

    Raises:
        ContainerInputError: The runner is not one ASH knows takes ``--env-file``,
            the temporary directory is inside the source or output directory, or
            a value holds a line break or a NUL, which the file cannot hold.
    """
    import tempfile

    runner_name = Path(runner).name.lower().removesuffix(".exe")
    if runner_name not in _OCI_RUNNER_CANDIDATES:
        raise ContainerInputError(
            f"The configuration reads {', '.join(names)} from the environment, and "
            f"through OCI_RUNNER_WRAPPER they are passed in an --env-file, which ASH "
            f"knows only {', '.join(_OCI_RUNNER_CANDIDATES)} to take, not {runner}. "
            "Write the values in the config file, or run without OCI_RUNNER_WRAPPER."
        )
    for name in names:
        if any(char in environ.get(name, "") for char in "\n\r\0"):
            raise ContainerInputError(
                f"The environment variable {name}, which the configuration reads, "
                "holds a line break or a NUL, which an --env-file cannot pass. Write "
                "the value in the config file instead."
            )
    directory = Path(tempfile.mkdtemp(prefix="ash-container-env-"))
    # Named in a record, so a SIGKILL that strands it can be told from a directory
    # that is merely old (container_leftovers.sweep_env_dirs).
    record_env_dir(directory)
    real = _real_path(directory)
    # By real path, and by the directories' identity (_is_at_or_above): a bind
    # mount or a case alias reaches the tree under another name.
    if any(
        real.is_relative_to(_real_path(tree)) or _is_at_or_above(tree, directory)
        for tree in (source_dir, output_dir)
    ):
        shutil.rmtree(directory, ignore_errors=True)
        raise ContainerInputError(
            f"The temporary directory {tempfile.gettempdir()} is inside the source or "
            "output directory, so the variables the configuration reads cannot be "
            "written for the container runner there. Set TMPDIR to a directory "
            "outside both."
        )
    path = directory / "container.env"
    from automated_security_helper.core.cancellation import (
        discard_die_now_cleanup,
        record_die_now_cleanup,
    )

    # Recorded BEFORE the write: a die-now ending (a second shutdown signal,
    # or a SIGTERM with no scan registered) re-raises under SIG_DFL, so the
    # caller's finally never runs, and the handlers remove the recorded
    # files instead. Recording first closes the window where the file holds
    # values but no record names it; the walk tolerates a path that was
    # never written. The caller discards the record in the same finally
    # that removes the directory.
    record_die_now_cleanup(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for name in names:
                if name in environ:
                    try:
                        handle.write(f"{name}={environ[name]}\n")
                    except UnicodeEncodeError:
                        # os.environ carries bytes that were not UTF-8 as lone
                        # surrogates, which the file's encoding cannot hold:
                        # the same named refusal as a line break, instead of a
                        # traceback at the write.
                        raise ContainerInputError(
                            f"The environment variable {name}, which the "
                            "configuration reads, holds bytes that are not "
                            "UTF-8, which an --env-file cannot carry. Write "
                            "the value in the config file instead."
                        ) from None
    except BaseException:
        # The removal first, as the run's own finally orders it, so no
        # die-now window is left where the file exists unrecorded; and the
        # record goes only once the file is gone, because an rmtree whose
        # errors are ignored can fail silently and would otherwise leave
        # the values file on disk with nothing left that knows to remove
        # it. The walk unlinks by recorded name and tolerates absence, so
        # keeping the record costs nothing.
        shutil.rmtree(directory, ignore_errors=True)
        if not os.path.exists(path):
            discard_die_now_cleanup(path)
        raise
    return directory, path


@contextlib.contextmanager
def _env_file(
    names: List[str],
    environ: Mapping[str, str],
    runner: str,
    source_dir: Path,
    output_dir: Path,
) -> Iterator[Tuple[Path, Path]]:
    """:func:`_write_env_file`, with the file removed and its record dropped on exit.

    Yields ``(directory, file)``. However the block ends, the directory is removed
    first and the record is dropped only once the file is really gone: an
    ``rmtree`` whose errors are ignored can fail silently, and the record is then
    all that is left to remove the file. The record itself is taken inside the
    writer, before the file exists. The writer is looked up, and the removal
    called, through this module, and the record's removal is imported at the call,
    as :func:`_write_env_file` does.
    """
    directory, path = _write_env_file(names, environ, runner, source_dir, output_dir)
    try:
        yield directory, path
    finally:
        shutil.rmtree(directory, ignore_errors=True)
        if not os.path.exists(path):
            from automated_security_helper.core.cancellation import (
                discard_die_now_cleanup,
            )

            discard_die_now_cleanup(path)


@contextlib.contextmanager
def _termination_raises(env_file_dir: Path | None) -> Iterator[None]:
    """While active, a SIGTERM still ends with the env-file ``finally`` run.

    The ``finally`` this guards removes *env_file_dir*. With None there is no
    file to remove and nothing to guard, so nothing is installed and SIGTERM
    keeps whatever semantics the caller gave it: a run with no env file never
    had its handler replaced over a cleanup it does not need.

    When the CLI's cooperative handler (``cancellation._handle_sigterm``) is
    installed and a scan is registered for it to stop
    (``shutdown_scopes_registered``), the handler is left alone: it sets the
    registered scope's event, ``run_cmd_direct``'s wait reads it and stops the
    runtime, and the ``ScanCancelled`` it raises unwinds through the same
    ``finally``. Replacing it here undid that stop for the whole run step: the
    first SIGTERM exited at once, with no stop line and the runtime left
    running. The registration is the condition, not the ambient cancel event:
    the ambient scope has a different owner, so it can be active with nothing
    registered, and the cooperative handler's no-scan branch re-raises the
    signal at the default disposition, which would end the process without
    the ``finally``. An ignored SIGTERM (``SIG_IGN``) is also left alone:
    it cannot end the process, so the ``finally`` needs no guard, and a relay
    would turn the ignore into an exit. Otherwise SIGTERM's installed
    disposition could end the process without the ``finally``, so the
    installed handler raises ``SystemExit(143)`` in the main thread instead,
    and the previous handler is restored afterwards. A callable handler
    someone installed is called first rather than discarded -- one that
    raises unwinds through the same ``finally``, and one that returns falls
    through to the exit -- except the cooperative handler without a
    registration, as above. A no-op off the main thread, where no handler can
    be set."""
    import signal

    from automated_security_helper.core.cancellation import (
        _handle_sigterm,
        shutdown_scopes_registered,
    )

    if env_file_dir is None:
        yield
        return
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    if (
        signal.getsignal(signal.SIGTERM) is _handle_sigterm
        and shutdown_scopes_registered()
    ):
        yield
        return

    previous = signal.getsignal(signal.SIGTERM)
    if previous is None or previous == signal.SIG_IGN:
        # None: the handler was installed outside Python, so it cannot be read
        # here and could not be put back; a relay installed over it would be
        # restored as None, which signal.signal refuses, after the run.
        yield
        return

    def _relay(signum, frame):
        if callable(previous) and previous is not _handle_sigterm:
            previous(signum, frame)
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, _relay)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _refuse_repository_config_in_a_workspace(
    config: str, config_files: List[Path], source_dir: Path
) -> None:
    """Refuse, in workspace mode, a mounted config from the workspace's own checkout.

    *source_dir* is the workspace root. A config outside the workspace's own tree
    is the operator's, as in a local workspace scan, and is mounted unmarked. One
    in the checkout around the workspace root, or reached through a link there
    (``sandbox_grants.files_inside`` over the root's trees), is the scanned
    repository's own file outside the tree the scan inside sees: a local
    workspace scan reads it in place and confines what it may set, and container
    mode refuses the run instead, fail closed, whichever file of its chain makes
    it so, before anything is built or mounted, so the scan inside never reads a
    repository-written file as the operator's. A config inside the workspace root
    mounts no file of its own: it is read through /src, in the scan inside's own
    tree.

    The rule applies to the file that becomes the inner scan's ``--config``: the
    ``--config`` itself, or, when none is named, the file ``ASH_CONFIG`` names. With
    a ``--config`` named, ``ASH_CONFIG``'s file rides as the base alone and is
    mounted marked instead.
    """
    from automated_security_helper.config.confinement_remedy import (
        KEEP_A_SETTING,
        KEEP_A_SETTING_BESIDE_A_LOCATED_FILE,
        KEEP_A_SETTING_WHEN_THE_WALK_STOPPED,
    )
    from automated_security_helper.config.sandbox_grants import (
        confined_files,
        scanned_trees,
    )

    trees = scanned_trees(Path(source_dir))
    # Each file once, in chain order: config_files holds the --config itself,
    # resolved, and the name it was given is judged too, for a link. The
    # fail-closed members decide, and this builds a sentence, so a member that
    # only an unfinished name walk admitted is kept apart: it is refused like
    # the rest, but the message cannot say where it sits.
    stopped_walk: Dict[str, bool] = {}
    for path in [*config_files, Path(config)]:
        judged = confined_files([path], trees, named=[path])
        if judged.members:
            key = path.as_posix()
            stopped_walk[key] = stopped_walk.get(key, True) and bool(judged.undecided)
    if not config_files or not stopped_walk:
        return
    located = [path for path, stopped in stopped_walk.items() if not stopped]
    undecided = [path for path, stopped in stopped_walk.items() if stopped]
    clauses = []
    if located:
        clauses.append(
            f"{', '.join(located)} is in the git "
            "checkout around the workspace root "
            f"{Path(source_dir).as_posix()}, or reached through a "
            "link there, and "
            "outside the workspace root, where the workspace scan inside the container "
            "cannot see it"
        )
    if undecided:
        clauses.append(
            f"whether {', '.join(undecided)} is in that checkout could not be "
            "decided (resolving its name stopped before the walk finished), "
            "which is read as the repository's"
        )
    # The cause is the repository's tier, so the message ends with the remedy the
    # local warnings end with, chosen as resolve_config does
    # (``_tier_two_source``): a file whose name walk stopped is not known to be in a
    # checkout, so moving it out is no remedy for it, and the walk has to finish.
    if not undecided:
        remedy = KEEP_A_SETTING
    elif located:
        remedy = KEEP_A_SETTING_BESIDE_A_LOCATED_FILE
    else:
        remedy = KEEP_A_SETTING_WHEN_THE_WALK_STOPPED
    # Raw values, like the link refusal's: the sinks show the message once.
    raise ContainerInputError(
        f"The config file '{config}' is the scanned repository's: "
        f"{'; '.join(clauses)}. Container mode refuses it in workspace mode. "
        "Keep --config, "
        "and every file it extends, outside the checkout around the workspace root. "
        f"{remedy}"
    )


def _require_mountable_inputs(
    source_dir: Path | str,
    output_dir: Path | str,
    config: str | None,
    workspace_config: str | None,
    workspace_relative_file: str | None,
    reads: OperatorConfigReads | None = None,
) -> None:
    """Check every host path a run would mount, before anything is built or run.

    The directories first, before anything resolves a path: a NUL byte is
    refused there (``_require_mountable_directories``), where resolving it
    would raise ValueError out of the check.
    """
    if reads is None:
        reads = OperatorConfigReads()
    _require_mountable_directories(source_dir, output_dir)
    _refuse_unusable_output_dir(source_dir, output_dir)
    source = _real_path(source_dir)
    if config:
        _refuse_config_linked_out_of_the_tree(config, source)
        _refuse_absolute_extends(config)
        _, _, config_files, _ = reads.host_file(
            config, source, CONTAINER_CONFIG_ROOT, follow_extends=True
        )
        if workspace_relative_file is not None:
            _refuse_repository_config_in_a_workspace(
                config, config_files, Path(source_dir)
            )
    env_config = reads.host_ash_config()
    if env_config is not None:
        _, _, env_files, _ = _mount_env_config(env_config, source, reads)
        # In workspace mode with no --config the variable's file becomes the
        # inner scan's --config (_assemble_run_command), so it is judged as the
        # --config above is. With a --config named, the file rides as the base
        # alone and keeps the mark it carries.
        if workspace_relative_file is not None and not config:
            _refuse_repository_config_in_a_workspace(
                env_config, env_files, Path(source_dir)
            )
        # Decided here, with the chain judged, so a command assembled from the
        # same record carries this answer (a run that builds starts a fresh
        # record and decides again). A workspace scan never asks (see
        # _assemble_run_command), and a scan that names its config never reads
        # the answer, so nothing is decided for either.
        if workspace_relative_file is None and not config:
            reads.env_config_is_the_scans_config(env_config, source_dir)
    if workspace_config and workspace_relative_file is not None:
        _refuse_config_linked_out_of_the_tree(
            workspace_config, source, "workspace policy"
        )
        _, _, policy_files, policy_plan = reads.host_file(
            workspace_config,
            source,
            CONTAINER_WORKSPACE_CONFIG_ROOT,
            follow_extends=False,
        )
        # Judged here, on the plan in hand, so a policy the scanned repository
        # wrote refuses the run before anything is cleared or built, as the
        # --config twin above does; command assembly applies it again.
        if policy_files:
            _refuse_repository_written_policy(
                workspace_config, Path(source_dir), policy_plan
            )


@_reading_chain_files_once
def container_input_refusal(
    source_dir: Path | str,
    output_dir: Path | str,
    config: str | None,
    workspace_config: str | None = None,
    workspace_relative_file: str | None = None,
    reads: OperatorConfigReads | None = None,
) -> str | None:
    """Why a container scan cannot be given its inputs as they are, or None.

    With *reads*, the config chain's walks are the scan's own
    (:class:`OperatorConfigReads`); without, this call keeps its own.

    The config file (:func:`_unreadable_config`), every host path the run would
    mount (:func:`_require_mountable_inputs`), and the variables the operator's
    config files read (:func:`operator_environment_names`). A refusal is exit 3,
    the code a local scan gives an unusable config. ``run_ash_container`` checks
    this before it builds anything; ``run_ash_scan`` checks it before it clears
    the previous run's output, so a refused scan leaves that output as it was.
    """
    refusal = _unreadable_config(config)
    if refusal is not None:
        return refusal
    if reads is None:
        reads = OperatorConfigReads()
    try:
        env_config = reads.host_ash_config()
        refusal = _unreadable_config(env_config)
        if refusal is not None:
            return refusal
        _require_mountable_inputs(
            source_dir,
            output_dir,
            config,
            workspace_config,
            workspace_relative_file,
            reads,
        )
        operator_environment_names(config, env_config, source_dir, reads)
    except ContainerInputError as e:
        return str(e)
    except RuntimeError as e:
        # Python 3.10 to 3.12 raise RuntimeError, not OSError, for a symlink
        # loop met while a path is resolved: that one is a refusal, not a
        # traceback. Any other RuntimeError (RecursionError and
        # NotImplementedError are subclasses, and so is a bug's) keeps its
        # traceback.
        if "symlink loop" not in str(e).lower():
            raise
        return (
            f"A path the container run would mount cannot be resolved: {e}. "
            "Container mode mounts the source, the output and the config by "
            "their real paths, so each has to resolve to a directory or a file."
        )
    return None


@_reading_chain_files_once
def _assemble_run_command(
    oci_command_prefix: List[str],
    resolved_oci_runner: str,
    image_name: str,
    source_dir: Path,
    output_dir: Path,
    offline: bool,
    debug: bool,
    color: bool,
    quiet: bool,
    progress: bool,
    verbose: bool,
    simple: bool,
    python_based_plugins_only: bool,
    cleanup: bool,
    inspect: bool,
    # See fail_on_incomplete_scanners at the end of this signature: its sibling,
    # kept there rather than here only because it needs a default and every
    # parameter between the two has none.
    fail_on_findings: bool | None,
    phases: List,
    scanners: List[str],
    exclude_scanners: List[str],
    output_formats: List,
    config: str | None,
    config_overrides: List[str],
    existing_results: str | None,
    ash_plugin_modules: List[str],
    strategy,
    ctx,
    container_network: str = "bridge",
    workspace_relative_file: str | None = None,
    allow_missing_projects: bool = False,
    shard_index: int | None = None,
    shard_count: int | None = None,
    fail_on_incomplete_scanners: bool | None = None,
    workspace_config: str | None = None,
    ignore_suppressions: bool = False,
    min_severity: str | None = None,
    log_level: AshLogLevel | str | None = None,
    outer_run_id: str | None = None,
    environment_names: List[str] | None = None,
    env_file: Path | None = None,
    reads: OperatorConfigReads | None = None,
    container_name: str | None = None,
    named_source: Path | str | None = None,
) -> List[str]:
    """Assemble the full `docker run` command list.

    Args:
        log_level: ``--log-level``, forwarded unless it is INFO, the inner
            default. ``--debug``, ``--verbose`` and ``--simple`` cover only three
            of the levels; ERROR, QUIET and TRACE reach the scan this way.
        ignore_suppressions: Forwarded as ``--ignore-suppressions``, because the
            suppressions are applied by the scan inside: the host recomputes the
            verdict from the ash.sarif that scan writes, which already carries
            them. The in-container scan also decides which files its scanners
            read, and under the flag every scanner reads the files under ignore
            paths; the host cannot count a finding no scanner produced.
        named_source: The source directory as the operator named it, which the
            refusal ahead of the build judged. The marks for the config files
            and the workspace refusals here are judged against it, so they
            agree with the variable names collected for the same scan. None
            judges against *source_dir*, which is what is mounted.
        container_name: A name for the container, or None for an unnamed one.
            A named container can be found and removed by a later start if this
            process dies before the runtime has stopped it
            (``interactions/container_leftovers``).
        reads: The scan's :class:`OperatorConfigReads`, so the mounts and marks
            are built from the chain walks the refusals already made. None
            makes this call's own.
        config: The host path of ``--config``. It is made readable in the
            container and the inner scan is given the path it has there; see
            :func:`_host_file_in_container`.
        workspace_config: In workspace mode, the host path of the workspace
            policy the host resolved, handed over the same way as
            ``--workspace-config``.
        outer_run_id: Handed to the in-container run, which writes it into its
            results file when it completes (utils/inner_run_outcome.py).
        environment_names: The variables the operator's config files read
            (:func:`operator_environment_names`), passed by name: the runner reads
            each value from its own environment.
        env_file: Through a wrapper, the file :func:`_write_env_file` wrote the
            same variables to, passed as ``--env-file`` instead.
        fail_on_incomplete_scanners: Whether the in-container scan should fail
            when a selected scanner did not complete, or None for unset. Defaults
            to None so that the many existing callers -- most of them tests
            building a command from a kwargs helper -- keep working; a required
            parameter here buys nothing, because the host recomputes the verdict
            from the results it reads back either way.
        shard_index: Zero-based shard index, or None for an unsharded scan.
        shard_count: Total shard count, or None. Emitted as a pair or not at all:
            the in-container CLI refuses a lone flag, so emitting one without the
            other would turn a host-side selection into a container-side usage
            error with no obvious cause.
        workspace_relative_file: In workspace mode, the workspace definition's
            path relative to *source_dir* -- which is the workspace root, and is
            what gets mounted at ``/src``. The in-container invocation then uses
            ``--workspace /src/<that>`` instead of ``--source-dir /src``, because
            the two flags are mutually exclusive and the container has to resolve
            the workspace itself: there is exactly one bind mount, so every
            project has to be reachable below ``/src``.
        allow_missing_projects: Passed through so a workspace with an
            uncloned project behaves the same inside the container as outside.

    Returns:
        A list of strings representing the complete run command.
    """
    _require_mountable("source directory", source_dir)
    _require_mountable("output directory", output_dir)
    _refuse_unusable_output_dir(source_dir, output_dir)
    if reads is None:
        reads = OperatorConfigReads()
    marks_source = Path(named_source) if named_source is not None else source_dir
    if environment_names and oci_command_prefix and env_file is None:
        raise ContainerInputError(
            "Through OCI_RUNNER_WRAPPER the variables the configuration reads are "
            "passed in an --env-file, and none was written."
        )
    cmd: List[str] = [*oci_command_prefix, resolved_oci_runner, "run", "--rm"]
    if container_name:
        cmd.extend(["--name", container_name])

    # Environment variables
    cmd.extend(
        [
            "-e",
            f"ASH_ACTUAL_SOURCE_DIR={source_dir}",
            "-e",
            f"ASH_ACTUAL_OUTPUT_DIR={output_dir}",
            "-e",
            f"ASH_DEBUG={'YES' if debug else 'NO'}",
        ]
    )
    if outer_run_id is not None:
        # By name: the runner reads the value from its own environment
        # (_run_environment), so it is not on a command line other processes on
        # the host can read. A wrapper such as sudo need not pass that environment
        # on, so through one the value goes on the command line.
        if oci_command_prefix:
            cmd.extend(["-e", f"{OUTER_RUN_ID_ENV}={outer_run_id}"])
        else:
            cmd.extend(["-e", OUTER_RUN_ID_ENV])

    # The mounted directory within its repository, worked out here because inside
    # the container it is always /src and git there sees only the mount (see
    # utils/scan_source.py). Always passed, empty when the host has no label, so
    # the scan in the container records none rather than asking git there. In
    # workspace mode it names the workspace mount, not a project.
    from automated_security_helper.utils.get_scan_set import git_repository_root
    from automated_security_helper.utils.scan_source import (
        SCAN_SOURCE_ENV,
        host_scan_source_label,
    )

    label = host_scan_source_label(source_dir, git_repository_root)
    cmd.extend(["-e", f"{SCAN_SOURCE_ENV}={label or ''}"])

    # What the operator's own config files read from the environment, which the
    # scan inside resolves as a local scan does. Never the values: by name, or
    # through a wrapper, the file that holds them.
    if env_file is not None:
        cmd.extend(["--env-file", str(env_file)])
    else:
        for name in environment_names or []:
            cmd.extend(["-e", name])

    # Source dir mount: read-only wherever the output directory is. The output has
    # its own mount at /out and the inner scan is told to write there, so nothing
    # has to write through /src -- also when the host output directory is inside
    # the source tree, which is the default (<source>/.ash/ash_output).
    cmd.extend(["--mount", f"type=bind,source={source_dir},destination=/src,readonly"])

    # Output dir mount
    cmd.extend(["--mount", f"type=bind,source={output_dir},destination=/out"])

    # The config files the operator named on the host, read-only. In workspace
    # mode that is the operator's --config, which /src never holds.
    inner_config = None
    config_from_scanned_repository = False
    marked_config_files: List[str] = []
    # The files of either chain in a git checkout other than the scanned one: not
    # the scanned tree's (no mark above), and not the operator's either.
    another_checkout_files: List[str] = []
    if config:
        _refuse_config_linked_out_of_the_tree(config, source_dir)
        _refuse_absolute_extends(config)
        config_mounts, inner_config, config_files, config_plan = reads.host_file(
            config, source_dir, CONTAINER_CONFIG_ROOT, follow_extends=True
        )
        cmd.extend(config_mounts)
        # A config inside the source directory is read through /src, which is the
        # inner scan's own tree, and mounts no host file; one mounted from elsewhere
        # needs the host's verdict, judged by its files and the name it was given,
        # in a one-directory scan and a workspace scan alike. In workspace mode a
        # config from the workspace's own checkout is refused, here as well as
        # before the build, so the rule holds whichever checks a caller ran first.
        if workspace_relative_file is not None:
            _refuse_repository_config_in_a_workspace(config, config_files, marks_source)
        if config_files:
            config_from_scanned_repository, marked_config_files = _config_marks(
                config, marks_source, config_plan
            )
            # A chain mark already makes every file of the chain the repository's.
            if not config_from_scanned_repository:
                another_checkout_files.extend(
                    _another_checkout_marks(config, config_plan, marked_config_files)
                )
    # The file the host's ASH_CONFIG names, which a local scan reads as its base
    # whatever names the config (_host_ash_config), mounted on its own, with each
    # file of its chain the host counts as repository-written marked on its own,
    # and each one in another git checkout marked as such.
    inner_env_config = None
    env_config = reads.host_ash_config()
    if env_config is not None:
        env_mounts, inner_env_config, env_files, env_plan = _mount_env_config(
            env_config, source_dir, reads
        )
        cmd.extend(env_mounts)
        # Here as well as before the build, so the rule holds for a caller that
        # reaches this function directly. Only where the variable's file becomes
        # the inner scan's --config; with a --config named it is the base alone.
        if workspace_relative_file is not None and not config:
            _refuse_repository_config_in_a_workspace(
                env_config, env_files, marks_source
            )
        if env_files:
            env_marked = _env_config_marks(env_config, marks_source, env_plan)
            marked_config_files = [*marked_config_files, *env_marked]
            another_checkout_files.extend(
                _another_checkout_marks(env_config, env_plan, env_marked)
            )
    inner_workspace_config = None
    if workspace_config and workspace_relative_file is not None:
        _refuse_config_linked_out_of_the_tree(
            workspace_config, source_dir, "workspace policy"
        )
        policy_mounts, inner_workspace_config, policy_files, policy_plan = (
            reads.host_file(
                workspace_config,
                source_dir,
                CONTAINER_WORKSPACE_CONFIG_ROOT,
                follow_extends=False,
            )
        )
        if policy_files:
            _refuse_repository_written_policy(
                workspace_config, marks_source, policy_plan
            )
        cmd.extend(policy_mounts)

    # Network: offline always uses none; container_network overrides otherwise
    if offline or container_network == "none":
        cmd.append("--network=none")
    elif container_network and container_network != "bridge":
        cmd.append(f"--network={container_network}")
    if offline:
        cmd.extend(["-e", "ASH_OFFLINE=YES"])
    # The operator's opt-in for tools inside the scanned tree applies to the scan the
    # container runs too; see utils/subprocess_utils.in_tree_tools_allowed.
    if in_tree_tools_allowed():
        cmd.extend(["-e", f"{ALLOW_IN_TREE_TOOLS_ENV}=1"])

    # Terminal size passthrough (matches ./ash lines 190-191)
    try:
        columns, lines = shutil.get_terminal_size()
        cmd.extend(["-e", f"COLUMNS={columns}", "-e", f"LINES={lines}"])
    except Exception as e:
        ASH_LOGGER.debug(f"Unable to determine terminal size via shutil: {e}")

    # TTY flag: attach pseudo-TTY when stdout is a terminal and color is on
    # (matches ./ash lines 193-195: COLOR_OUTPUT=true && [ -t 1 ])
    if color and sys.stdout.isatty():
        cmd.append("-t")

    # The runner markers: by name, or through a wrapper with their values. A value
    # the command line cannot take has already been refused, before any build.
    cmd.extend(_runner_marker_args(oci_command_prefix, snapshot_environ()))

    # Image name then ash subcommand
    cmd.append(image_name)
    cmd.append("ash")

    # Core ASH path arguments. In workspace mode --source-dir is omitted, because
    # it is mutually exclusive with --workspace and the workspace root is already
    # the mount point.
    if workspace_relative_file is not None:
        cmd.extend(
            ["--workspace", f"/src/{workspace_relative_file}", "--output-dir", "/out"]
        )
        if inner_workspace_config is not None:
            cmd.extend(["--workspace-config", inner_workspace_config])
        if allow_missing_projects:
            cmd.append("--allow-missing-projects")
    else:
        cmd.extend(["--source-dir", "/src", "--output-dir", "/out"])

    # Build ash_args from context + parameters
    ash_args: List[str] = []
    if ctx and hasattr(ctx, "args"):
        ash_args = list(ctx.args or [])

    if quiet:
        ash_args.append("--quiet")
    if not progress:
        ash_args.append("--no-progress")
    if not color:
        ash_args.append("--no-color")
    if debug:
        ash_args.append("--debug")
    if verbose:
        ash_args.append("--verbose")
    log_level_value = getattr(log_level, "value", log_level)
    if log_level_value is not None and log_level_value != AshLogLevel.INFO.value:
        ash_args.extend(["--log-level", str(log_level_value)])
    if simple:
        ash_args.append("--simple")
    if python_based_plugins_only:
        ash_args.append("--python-based-plugins-only")
    if cleanup:
        ash_args.append("--cleanup")
    if inspect:
        ash_args.append("--inspect")
    if fail_on_findings:
        ash_args.append("--fail-on-findings")
    elif fail_on_findings is not None:
        ash_args.append("--no-fail-on-findings")
    # Forwarded so the in-container scan reaches the same verdict the host will.
    # The host recomputes the exit code from the results it reads back, so a
    # dropped flag would not change the final code -- but it would make the
    # container print a clean summary for a scan the host then fails, and the
    # container's log is what an operator reads first.
    if fail_on_incomplete_scanners:
        ash_args.append("--fail-on-incomplete-scanners")
    elif fail_on_incomplete_scanners is not None:
        ash_args.append("--no-fail-on-incomplete-scanners")
    if ignore_suppressions:
        ash_args.append("--ignore-suppressions")
    # Forwarded in workspace mode only. The host returns a workspace scan's
    # exit code as the container computed it, so a minimum it never saw was
    # applied nowhere; a one-directory scan's exit code is recomputed on the
    # host, where --min-severity is applied, and forwarding it there would
    # have the container print a clean summary the host then judges again.
    if (
        workspace_relative_file is not None
        and min_severity
        and str(min_severity).lower() != "low"
    ):
        ash_args.extend(["--min-severity", str(min_severity)])

    for phase in phases:
        ash_args.extend(
            ["--phases", phase.value if hasattr(phase, "value") else str(phase)]
        )

    for scanner in scanners:
        ash_args.extend(["--scanners", scanner])

    for scanner in exclude_scanners:
        ash_args.extend(["--exclude-scanners", scanner])

    for fmt in output_formats:
        ash_args.extend(
            ["--output-formats", fmt.value if hasattr(fmt, "value") else str(fmt)]
        )

    # In workspace mode source_dir is the workspace root, where each project has
    # its own config and a single-directory discovery says nothing about them, so
    # the mounted file is named as it always was.
    env_config_named = (
        inner_config is None
        and inner_env_config is not None
        and (
            workspace_relative_file is not None
            or reads.env_config_is_the_scans_config(env_config, source_dir)
        )
    )
    if inner_config is not None:
        ash_args.extend(["--config", inner_config])
    elif env_config_named and inner_env_config is not None:
        # With no --config, the mounted file is named to the scan inside in two
        # cases: a scan of one directory that holds nothing discoverable, where a
        # local scan reads the ASH_CONFIG file as its config, and a workspace
        # scan, which asks no discovery question and names the file whatever the
        # workspace root holds. With a discoverable config in a one-directory
        # scan the inner scan is left to discover /src's own file, and the
        # mounted file rides as the base alone (ASH_CONFIG_FROM_HOST_FLAG).
        # env_config_named already requires the mounted path; the second test
        # only narrows its type.
        # This is the caller that leaves config unset. The CLI's --config
        # option reads ASH_CONFIG itself, so a command-line scan arrives with
        # the file as config and never gets here, and ./ash names the file the
        # same way, discoverable config or not.
        ash_args.extend(["--config", inner_env_config])
    if inner_env_config is not None:
        ash_args.extend([ASH_CONFIG_FROM_HOST_FLAG, inner_env_config])
    if config_from_scanned_repository or (
        env_config_named and inner_env_config in marked_config_files
    ):
        ash_args.append(CONFIG_FROM_SCANNED_REPOSITORY_FLAG)
    for marked in marked_config_files:
        ash_args.extend([CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG, marked])
    for marked in another_checkout_files:
        ash_args.extend([CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG, marked])

    for override in config_overrides:
        ash_args.extend(["--config-overrides", override])

    if existing_results:
        # Truthiness here and truthiness in _discard_prior_run_artifacts, which grants the
        # matching exemption from the pre-run cleanup. The two have to agree on the empty
        # string or it falls between them: the host would keep a previous run's results
        # file for an inner scan that was never asked to read it, and then read that file
        # back as this invocation's own.
        #
        # `--use-existing`, not `--existing-results`. The latter is not declared anywhere
        # on the CLI -- it exists only as a local variable in cli/scan.py, where
        # --use-existing is resolved into the path this parameter carries -- and the
        # container entrypoint is that same CLI, so the flag is a usage error inside.
        # That usage error exits ASH_EXIT_USAGE_ERROR, not 2 (ASH's code for actionable
        # findings), and the host passes it through as a non-verdict, so its read-back
        # does not take the rejected invocation for a dirty scan.
        #
        # The value would be wrong in the container regardless: it is a host path, and the
        # output directory is bind-mounted at /out. --use-existing resolves
        # ash_aggregated_results.json from the inner --output-dir, which is the same file
        # through that mount, so this reproduces the host's own resolution rather than
        # re-sending a path the container cannot reach.
        expected = Path(output_dir).joinpath("ash_aggregated_results.json")
        if Path(existing_results).resolve() != expected.resolve():
            ASH_LOGGER.warning(
                f"--existing-results was given {existing_results}, which is not "
                f"{expected.as_posix()}. The container mounts only the output directory, "
                "and the in-container scan reads that directory's own "
                "ash_aggregated_results.json, so the named file will not be the one used."
            )
        ash_args.append("--use-existing")

    for module in ash_plugin_modules:
        ash_args.extend(["--ash-plugin-modules", module])

    if strategy:
        ash_args.extend(
            [
                "--strategy",
                strategy.value if hasattr(strategy, "value") else str(strategy),
            ]
        )

    # Both or neither, and not via the ASH_SHARD_* environment variables: this
    # command forwards only a fixed set of variables into the container, so a
    # matrix that set the env vars on the host would otherwise get an unsharded
    # container scan while every job believed it was one shard of several.
    if shard_index is not None and shard_count is not None:
        ash_args.extend(
            [
                "--shard-index",
                str(shard_index),
                "--shard-count",
                str(shard_count),
            ]
        )

    ash_args.append("--no-show-summary")

    cmd.extend(ash_args)
    return cmd


def _run_environment(outer_run_id: str | None) -> Dict[str, str] | None:
    """The container runner's environment: this process's, with the outer run's ID.

    ``_assemble_run_command`` names the ID with ``-e`` and no value, and the runner
    reads it from here. None, meaning this process's own environment, without one.
    """
    if outer_run_id is None:
        return None
    from automated_security_helper.utils.process_env import snapshot_environ

    return {**snapshot_environ(), OUTER_RUN_ID_ENV: outer_run_id}


def _execute_container(cmd: List[str], debug: bool, env: Dict[str, str] | None = None):
    """Run the assembled container command and return the result.

    Returns:
        subprocess.CompletedProcess on success, CalledProcessError on failure.
    """
    from automated_security_helper.utils.error_text import text_without_values

    echo("Running ASH scan using built image...")
    # Each --config-overrides value as its key: it can be a credential. The
    # run's environment values hidden too (the spawn's carrier, set by the
    # caller): a mount source for a base the environment chose, or an -e
    # pair's text, holds the variable's value, which shown_arguments alone
    # leaves in place. Kept on the result (shown_command) so the caller's own
    # debug dump prints the same text instead of joining the raw arguments.
    shown = " ".join(map(str, subprocess_utils.shown_arguments(cmd)))
    shown = text_without_values(shown, subprocess_utils._SPAWN_VALUES.get())
    if debug:
        echo(f"Running container command: {shown}")
    # The values the run carries (the spawn's recorded values) are hidden in the
    # streamed copy of the child's output line by line; the copy kept on the
    # result is hidden the same way, each line of a value that holds a line
    # break included (_value_lines, as the stream has it), so a caller that
    # prints or logs it after the run, when the record is gone, cannot show them.
    carried = _value_lines(
        tuple(subprocess_utils._SPAWN_VALUES.get())
        + tuple(subprocess_utils._SPAWN_STRICT_VALUES.get())
    )

    def hidden(text):
        return text_without_values(text, carried) if isinstance(text, str) else text

    try:
        result = run_cmd_direct(cmd, debug=debug, env=env)
        result.stdout = hidden(result.stdout)
        result.stderr = hidden(result.stderr)
        result.shown_command = shown
        if debug:
            echo(f"Container execution completed with return code: {result.returncode}")
        return result
    except CalledProcessError as e:
        e.output = hidden(e.output)
        e.stderr = hidden(e.stderr)
        e.shown_command = shown
        if debug:
            # The command as it may be shown (each --config-overrides value as its
            # key): str(e) quotes the raw argv, override values included.
            echo(
                f"Container execution failed with code {e.returncode}: "
                f"Command '{shown}' returned non-zero exit status {e.returncode}."
            )
        return e
    except OSError as e:
        if not getattr(e, RUNTIME_NOT_STARTED_ATTRIBUTE, False):
            # Raised after the runtime started (a signal to it refused, a pipe
            # closed under the wait): the container may be running, so this is
            # a failed run and not one that never started. Reported as the
            # non-zero status the caller already handles, with the record of
            # the container left for the next sweep.
            message = f"The container runtime failed while it ran: {hidden(str(e))}"
            echo(message, err=True)
            failed = create_completed_process(
                args=[], returncode=1, stdout="", stderr=message
            )
            setattr(failed, _MAY_STILL_RUN_ATTR, True)
            return failed
        # The runtime could not be started (a runner path that is gone, a
        # permission the host refuses). Reported as a run that never started,
        # so the caller exits with the refusal's code instead of a traceback
        # and drops the record of a container that never existed.
        message = f"The container runtime could not be started: {hidden(str(e))}"
        echo(message, err=True)
        return _not_started(
            create_completed_process(args=[], returncode=1, stdout="", stderr=message)
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_ash_container(
    ctx=None,
    source_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
    log_level: AshLogLevel = AshLogLevel.INFO,
    config: str | None = None,
    config_overrides: List[str] | None = None,
    offline: bool = False,
    strategy: ExecutionStrategy = ExecutionStrategy.PARALLEL.value,
    scanners: List[str] | None = None,
    exclude_scanners: List[str] | None = None,
    progress: bool = True,
    output_formats: List[ExportFormat] | None = None,
    cleanup: bool = False,
    phases: List[ExecutionPhase] | None = None,
    inspect: bool = False,
    existing_results: str | None = None,
    python_based_plugins_only: bool = False,
    quiet: bool = False,
    simple: bool = False,
    verbose: bool = False,
    debug: bool = False,
    color: bool = True,
    fail_on_findings: bool | None = None,
    fail_on_incomplete_scanners: bool | None = None,
    # Container-specific args
    build: bool = True,
    run: bool = True,
    force: bool = False,
    oci_runner: str | None = None,
    build_target: BuildTarget | None = None,
    offline_semgrep_rulesets: str = "p/ci",
    container_uid: str | None = None,
    container_gid: str | None = None,
    ash_revision_to_install: str | None = None,
    custom_containerfile: str | None = None,
    custom_build_arg: List[str] | None = None,
    ash_plugin_modules: List[str] | None = None,
    container_network: str = "bridge",
    workspace_relative_file: str | None = None,
    allow_missing_projects: bool = False,
    shard_index: int | None = None,
    shard_count: int | None = None,
    workspace_config: str | None = None,
    ignore_suppressions: bool = False,
    min_severity: str | None = None,
    outer_run_id: str | None = None,
    reads: OperatorConfigReads | None = None,
):
    """Build and run the ASH container image.

    Args:
        reads: The scan's :class:`OperatorConfigReads`, when the caller already
            read the operator's config chain for the same scan; None starts
            this run's own.
        ctx: Typer context object
        source_dir: Path to the directory containing the code/files you wish to scan
        output_dir: Path to the directory that will contain the report of the scans
        build: Whether to build the ASH container image
        run: Whether to run the ASH container image
        force: Force rebuild of the ASH container image
        quiet: Don't print verbose text about the build process
        oci_runner: Use the specified OCI runner instead of docker to run the containerized tools
        build_target: The image stage to build and run. None means ``non-root``;
            CI environment variables do not change it (see _resolve_build_target).
        offline: Build ASH for offline execution
        offline_semgrep_rulesets: Specify Semgrep rulesets for use in ASH offline mode
        container_uid: UID to use for the container user
        container_gid: GID to use for the container user
        verbose: Enable verbose logging
        debug: Enable debug logging
        color: Enable/disable colorized output
        workspace_relative_file: In workspace mode, the workspace definition's
            path relative to source_dir. source_dir is then the workspace root
            rather than a project, and the container resolves the workspace and
            scans each project below the single /src mount.
        allow_missing_projects: Passed through to the in-container invocation.
        shard_index: Zero-based shard index, forwarded to the in-container
            invocation. Forwarded rather than dropped because dropping it would
            have every shard scan the whole repository, and merging does not
            deduplicate -- see _run_container_mode's docstring.
        shard_count: Total shard count, forwarded alongside shard_index.
        config: Host path of the config file. Mounted read-only for the inner
            scan; one that is not an existing file refuses the run with exit 3
            before anything is built.
        workspace_config: Host path of the workspace policy the host resolved,
            mounted and forwarded as ``--workspace-config``.
        outer_run_id: Handed to the in-container run, which writes it into its
            results file when it completes (utils/inner_run_outcome.py).
        ignore_suppressions: Forwarded to the in-container invocation, so its
            scanners read the files under ignore paths.

    Returns:
        CompletedProcess: The result of the container execution
    """
    # Resolve cwd-based defaults at call time (not import time).
    if source_dir is None:
        source_dir = Path.cwd().as_posix()
    if output_dir is None:
        output_dir = Path.cwd().joinpath(".ash", "ash_output").as_posix()

    # Rebind mutable defaults so each call gets its own collection.
    if config_overrides is None:
        config_overrides = []
    if scanners is None:
        scanners = []
    if exclude_scanners is None:
        exclude_scanners = []
    if output_formats is None:
        output_formats = []
    if phases is None:
        phases = [ExecutionPhase.CONVERT, ExecutionPhase.SCAN, ExecutionPhase.REPORT]
    if custom_build_arg is None:
        custom_build_arg = []
    if ash_plugin_modules is None:
        ash_plugin_modules = []

    # Before any build: a scan that cannot be given its config, or whose paths the
    # runner cannot mount, is not worth one. These are the inputs the run phase
    # mounts, the default output directory included, checked as they will be
    # mounted and before anything is created, so a refused run makes nothing.
    # Only when a run was asked for: a build mounts nothing and reads none of
    # these inputs, so with run=False there is nothing to check them against.
    # The source directory as the operator named it. The variable names, the
    # marks and the workspace refusals of this scan are judged against this one
    # spelling in both phases, so they agree; the run phase below replaces
    # source_dir with its resolved form for the mounts.
    named_source = source_dir or Path.cwd()
    mounted_output = output_dir or Path(named_source).joinpath("ash_output")
    if reads is None:
        reads = OperatorConfigReads()
    config_refusal = None
    if run:
        config_refusal = container_input_refusal(
            named_source,
            mounted_output,
            config,
            workspace_config,
            workspace_relative_file,
            reads,
        )
    if config_refusal is not None:
        # It can name a path inside the scanned tree: the whole raw message is
        # shown once, on one line, like the refusals below.
        secho(shown_on_one_line(config_refusal), fg=typer.colors.RED)
        return _not_started(
            create_completed_process(
                args=[], returncode=3, stdout="", stderr=config_refusal
            )
        )

    # Get host UID and GID using safe subprocess calls
    try:
        host_uid = subprocess_utils.get_host_uid()
        host_gid = subprocess_utils.get_host_gid()
    except Exception as e:
        secho(f"Error getting user ID information: {e}", fg=typer.colors.RED)
        return _not_started(
            create_completed_process(args=[], returncode=1, stdout="", stderr=str(e))
        )

    # The IDs, the revision and a non-root build as UID or GID 0, before the runner is
    # resolved or anything is built; run_ash_scan checks the same before it clears
    # the previous run's output. Exit 3, as ./ash and Invoke-ASH refuse the same
    # input, and 1 for the revision.
    build_refusal = container_build_refusal(
        build=build,
        build_target=build_target,
        custom_containerfile=custom_containerfile,
        container_uid=container_uid,
        container_gid=container_gid,
        ash_revision_to_install=ash_revision_to_install,
        host_uid=host_uid,
        host_gid=host_gid,
    )
    if build_refusal is not None:
        code, message = build_refusal
        secho(message, fg=typer.colors.RED)
        return _not_started(
            create_completed_process(
                args=[], returncode=code, stdout="", stderr=message
            )
        )
    if container_uid is None:
        container_uid = str(host_uid)
    if container_gid is None:
        container_gid = str(host_gid)

    # Resolve OCI runner
    try:
        resolved_oci_runner = _resolve_oci_runner(oci_runner)
    except RuntimeError as e:
        secho(str(e), fg=typer.colors.RED)
        return _not_started(
            create_completed_process(args=[], returncode=1, stdout="", stderr=str(e))
        )

    oci_command_prefix = _get_oci_wrapper_prefix()

    if run:
        # A runner marker the wrapper's command line cannot take is refused here,
        # before anything is built, with exit 3 as ./ash refuses it.
        try:
            _runner_marker_args(oci_command_prefix, snapshot_environ())
        except RunnerMarkerRefused as e:
            secho(str(e), fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=3, stdout="", stderr=str(e)
                )
            )

    # Resolve ASH revision. One given was checked above (container_build_refusal);
    # an explicit revision decides the build, and the install is consulted (and
    # logs which source it builds from) only when none was given.
    if ash_revision_to_install is not None:
        resolved_revision = ash_revision_to_install
    else:
        resolved_revision = get_ash_revision()

    # Only a build installs the revision, so only a build is refused for one the
    # build cannot take. A revision derived from the install (a direct_url.json
    # with an odd ref) refused a --no-build run that would have installed nothing.
    if build and resolved_revision is not None and resolved_revision != "LOCAL":
        if not _validate_ash_revision(resolved_revision):
            message = _invalid_revision_message(resolved_revision)
            secho(message, fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=message
                )
            )

    # The provenance line prints only once the revision passed validation,
    # whose accepted characters cannot carry a control character, so the
    # line never emits one; a refused revision is named by the refusal
    # alone, which escapes the value.
    if ash_revision_to_install is not None:
        ASH_LOGGER.info(
            f"Building with ASH revision {resolved_revision} "
            "(--ash-revision-to-install)"
        )

    resolved_build_target = _resolve_build_target(build_target, custom_containerfile)
    # An empty ASH_IMAGE_NAME names no image, as in ./ash and Invoke-ASH.
    ash_base_image_name = (
        os.environ.get("ASH_IMAGE_NAME")
        or f"automated-security-helper:{resolved_build_target}"
    )
    if (
        not build
        and custom_containerfile is not None
        and not os.environ.get("ASH_IMAGE_NAME")
    ):
        # A build with --custom-containerfile tags its result as the custom
        # image (_build_custom_image) and runs that. With --no-build the same
        # option names the image a build produced, so the run uses it too: the
        # stock ci image it ran instead is the custom image's base, as root and
        # without the custom tooling.
        ash_base_image_name = "automated-security-helper:custom"
    # Held to the characters ./ash and Invoke-ASH take, with their message and code,
    # before anything is built or run: a name that starts with '-' reaches the runner
    # as an option of its own, and no image name holds any other character. The whole
    # refusal is shown with shown_on_one_line, so a tab, newline or carriage return in
    # the value is written as \x09, \x0a or \x0d and the refusal stays one line; secho
    # leaves the ShownText as it is. The result keeps the message as it was written.
    if ash_base_image_name.startswith("-") or not _IMAGE_NAME_PATTERN.fullmatch(
        ash_base_image_name
    ):
        message = (
            f"The image name '{ash_base_image_name}' starts with '-', "
            "which the container runtime would read as an option, or holds a "
            "character other than A-Z, a-z, 0-9 and . _ : / @ -, which no image name "
            "does. Name an image with only those characters, not starting with '-'."
        )
        secho(shown_on_one_line(message), fg=typer.colors.RED)
        return _not_started(
            create_completed_process(
                args=[], returncode=_WRAPPER_REFUSAL_EXIT, stdout="", stderr=message
            )
        )

    # ASH_BASE_IMAGE_OVERRIDE is read only by a build, which puts it in the BASE_IMAGE
    # build argument. It is held to the image-name characters, as both wrappers hold
    # it, with their message and code, before anything is built. The value is checked
    # as it is, not trimmed, so a newline or a space at either end, or a value of only
    # whitespace, is refused as the wrappers refuse it; only an empty one is unset and
    # redirects nothing. The refusal is shown on one line, as the image name's is.
    base_image_override = os.environ.get("ASH_BASE_IMAGE_OVERRIDE", "")
    if (
        build
        and base_image_override
        and (
            base_image_override.startswith("-")
            or not _IMAGE_NAME_PATTERN.fullmatch(base_image_override)
        )
    ):
        message = (
            f"ASH_BASE_IMAGE_OVERRIDE '{base_image_override}' starts "
            "with '-' or holds a character other than A-Z, a-z, 0-9 and . _ : / @ -, "
            "which no image reference does. Name an image reference with only those "
            "characters, or unset it to build from the Dockerfile's own base image "
            "reference."
        )
        secho(shown_on_one_line(message), fg=typer.colors.RED)
        return _not_started(
            create_completed_process(
                args=[], returncode=_WRAPPER_REFUSAL_EXIT, stdout="", stderr=message
            )
        )

    # The values the operator's chain reads from the environment ride the
    # build's spawns as they ride the run's: a --build-arg the operator
    # expanded such a value into prints redacted, in the debug command echoes
    # and in a failed build's error text. A chain this read refuses was
    # already refused above when a run was asked for, so the catch is for a
    # build alone, which keeps building as it did, with no values to carry;
    # the run phase still refuses such a chain before any container sees it.
    try:
        build_hidden = tuple(
            value
            for name in operator_environment_names(
                config, reads.host_ash_config(), named_source, reads
            )
            for value in (os.environ.get(name, ""),)
            if value
        )
    except ContainerInputError:
        build_hidden = ()

    # Build phase (a non-root build as UID or GID 0 was refused above)
    if build:
        # Only a build reads the Dockerfile. --no-build runs an image that is already
        # present, so looking one up first refused a scan with a LOCAL revision and no
        # ASH source tree beside the package or recorded for it, although nothing was
        # going to be built. The same holds for the revision: only a build
        # installs one, so only a build is refused for having none.
        if resolved_revision is None:
            message = _unresolved_revision_message()
            secho(message, fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=message
                )
            )
        try:
            dockerfile_path = _find_dockerfile(resolved_revision)
        except FileNotFoundError as e:
            secho(str(e), fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )
            )

        try:
            with subprocess_utils._spawn_values(build_hidden):
                _build_image(
                    oci_command_prefix=oci_command_prefix,
                    resolved_oci_runner=resolved_oci_runner,
                    dockerfile_path=dockerfile_path,
                    image_name=ash_base_image_name,
                    build_target=resolved_build_target,
                    container_uid=container_uid,
                    container_gid=container_gid,
                    resolved_revision=resolved_revision,
                    offline=offline,
                    offline_semgrep_rulesets=offline_semgrep_rulesets,
                    force=force,
                    quiet=quiet,
                    custom_build_arg=custom_build_arg,
                    debug=debug,
                )

                if custom_containerfile is not None:
                    ash_base_image_name = _build_custom_image(
                        oci_command_prefix=oci_command_prefix,
                        resolved_oci_runner=resolved_oci_runner,
                        base_image_name=ash_base_image_name,
                        custom_containerfile=custom_containerfile,
                        quiet=quiet,
                        debug=debug,
                        target=_custom_containerfile_stage(
                            build_target, custom_containerfile
                        ),
                        force=force,
                    )

        except Exception as e:
            # A failed command's own text quotes its full argv; it is shown
            # the way the run's own command text is shown, never raw. The
            # handler runs outside the spawn context, so the carried values
            # are passed to it explicitly.
            secho(
                f"Error building ASH image: {_shown_build_failure(e, build_hidden)}",
                fg=typer.colors.RED,
            )
            if debug:
                # The captured output can quote a carried value back (the
                # build received it in --build-arg), so the dump hides the
                # carried values the way the error text above does. Redacted,
                # never dropped: the rest of the output is the diagnostic.
                from automated_security_helper.utils.error_text import (
                    text_without_values,
                )

                if hasattr(e, "stdout"):
                    echo(
                        "Build stdout: "
                        + text_without_values(str(e.stdout or ""), build_hidden)
                    )
                if hasattr(e, "stderr"):
                    echo(
                        "Build stderr: "
                        + text_without_values(str(e.stderr or ""), build_hidden)
                    )
            if isinstance(e, CalledProcessError):
                return _not_started(e)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )
            )

    # Run phase
    if run:
        if build:
            # The record above served the refusals and the build. The container
            # reads the operator's files when it starts, so the run phase reads
            # the chain afresh: the mounts, the marks and the variable names
            # must describe the files as they are after the build, not as they
            # were before it. One extra walk costs nothing beside a build.
            reads = OperatorConfigReads()
        if source_dir:
            try:
                source_dir = validate_path(source_dir)
            except ValueError as e:
                secho(str(e), fg=typer.colors.RED)
                return _not_started(
                    create_completed_process(
                        args=[], returncode=1, stdout="", stderr=str(e)
                    )
                )

        if not source_dir:
            source_dir = Path.cwd()
            ASH_LOGGER.info(f"Using current directory as source: {source_dir}")

        # The link rule once more, on the paths as given, right before the
        # directory is made: the check ahead of the build judged the paths as
        # they were then, and a link that appeared during the build would
        # otherwise be created through and resolved past here. The source
        # under the name the operator gave (named_source), as the first check
        # had it: the rule looks below the source under its given name and its
        # real path, and source_dir is the resolved one by now.
        try:
            _refuse_linked_output_dir(named_source, output_dir)
        except ContainerOutputLinkRefused as e:
            secho(shown_on_one_line(str(e)), fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=3, stdout="", stderr=str(e)
                )
            )
        try:
            if output_dir:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                output_dir = output_dir.resolve()
            else:
                # The default is made under the same guard as a named one: a
                # directory that cannot be made is a run that never started,
                # not a traceback.
                output_dir = source_dir.joinpath("ash_output")
                output_dir.mkdir(parents=True, exist_ok=True)
                ASH_LOGGER.info(f"Using default output directory: {output_dir}")
        except Exception as e:
            secho(f"Error creating output directory: {e}", fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )
            )

        container_name = new_container_name()
        env_file_dir: Path | None = None
        env_file: Path | None = None
        env_file_scope = contextlib.ExitStack()
        # The env file is removed however the run ends: a failure, Ctrl-C
        # (KeyboardInterrupt) or SIGTERM (_termination_raises) all reach the finally.
        # The write is inside this try, so an exit between it and the run is cleaned
        # up too. What no code can close is the store of the returned pair into the
        # names below, and the push of the exit after the writer returns. Nor the
        # window between the write and the entry into _termination_raises below:
        # a SIGTERM at its default disposition there ends the process with no
        # finally. The directory is recorded as it is made (record_env_dir), so
        # the next container- or nix-mode start's sweep deletes it, unread.
        try:
            try:
                # The source as the refusal ahead of the build judged it, so the
                # record answers from the computation that refusal made.
                environment_names = operator_environment_names(
                    config, reads.host_ash_config(), named_source, reads
                )
                if environment_names and oci_command_prefix:
                    env_file_dir, env_file = env_file_scope.enter_context(
                        _env_file(
                            environment_names,
                            snapshot_environ(),
                            resolved_oci_runner,
                            Path(source_dir),
                            Path(output_dir),
                        )
                    )
            except ContainerInputError as e:
                # It names variables the configuration reads, and the configuration
                # can come from the scanned tree.
                secho(shown_on_one_line(str(e)), fg=typer.colors.RED)
                return _not_started(
                    create_completed_process(
                        args=[], returncode=3, stdout="", stderr=str(e)
                    )
                )
            try:
                run_cmd = _assemble_run_command(
                    container_name=container_name,
                    oci_command_prefix=oci_command_prefix,
                    resolved_oci_runner=resolved_oci_runner,
                    image_name=ash_base_image_name,
                    source_dir=source_dir,
                    output_dir=output_dir,
                    offline=offline,
                    debug=debug,
                    color=color,
                    quiet=quiet,
                    progress=progress,
                    verbose=verbose,
                    simple=simple,
                    python_based_plugins_only=python_based_plugins_only,
                    cleanup=cleanup,
                    inspect=inspect,
                    fail_on_findings=fail_on_findings,
                    fail_on_incomplete_scanners=fail_on_incomplete_scanners,
                    phases=phases,
                    scanners=scanners,
                    exclude_scanners=exclude_scanners,
                    output_formats=output_formats,
                    config=config,
                    config_overrides=config_overrides,
                    existing_results=existing_results,
                    ash_plugin_modules=ash_plugin_modules,
                    strategy=strategy,
                    ctx=ctx,
                    container_network=container_network,
                    workspace_relative_file=workspace_relative_file,
                    allow_missing_projects=allow_missing_projects,
                    shard_index=shard_index,
                    shard_count=shard_count,
                    workspace_config=workspace_config,
                    ignore_suppressions=ignore_suppressions,
                    min_severity=min_severity,
                    log_level=log_level,
                    outer_run_id=outer_run_id,
                    environment_names=environment_names,
                    env_file=env_file,
                    reads=reads,
                    named_source=named_source,
                )
            except ContainerInputError as e:
                # Checked before the build already; this catches a path that only
                # became unmountable once resolved here. It can name a path inside
                # the scanned tree.
                secho(shown_on_one_line(str(e)), fg=typer.colors.RED)
                return _not_started(
                    create_completed_process(
                        args=[], returncode=3, stdout="", stderr=str(e)
                    )
                )

            # The values the chain reads from the environment ride the spawn's
            # carrier, so the debug echoes and the stop paths' lines name the
            # command without them. The secret-named subset rides the strict
            # carrier: the streamed report never gives those the bare-word
            # exemption.
            hidden, strict = _carried_values_by_band(environment_names)
            with subprocess_utils._spawn_values(
                hidden, strict=strict, scan_report=True
            ):
                with _termination_raises(env_file_dir):
                    # Recorded before the runtime starts. An exception out of the
                    # run (an interrupt, a cancel) leaves the record for the next
                    # start's sweep; a run that ended on its own leaves the
                    # container gone with --rm.
                    record = record_container(
                        container_name, [*oci_command_prefix, resolved_oci_runner]
                    )
                    result = _execute_container(
                        run_cmd, debug=debug, env=_run_environment(outer_run_id)
                    )
                    code = getattr(result, "returncode", None)
                    ended_by_signal = isinstance(code, int) and code < 0
                    may_still_run = getattr(result, _MAY_STILL_RUN_ATTR, False)
                    if not (ended_by_signal or may_still_run):
                        # A client the kernel ended by a signal says nothing of
                        # its container, and neither does a failure raised while
                        # the runtime ran: the record stays for the next sweep.
                        discard_record(record)
                    return result
        finally:
            # The directory first, then the record once the file is gone
            # (_env_file); nothing is left to close when no file was written.
            env_file_scope.close()

    # Built but not run
    return create_completed_process(args=[], returncode=0, stdout="", stderr="")
