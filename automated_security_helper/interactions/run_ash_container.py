# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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
    SubprocessError,
)  # nosec B404 - Using the exception classes to evaluate subprocess invocations
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse
from urllib.request import url2pathname
import typer
import threading
import io
from importlib_metadata import import_module

# Import subprocess utilities
from automated_security_helper.core.constants import (
    ASH_ASSETS_DIR,
    ASH_REPO_LATEST_REVISION,
)
from automated_security_helper.core.enums import (
    AshLogLevel,
    BuildTarget,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    create_completed_process,
    in_tree_tools_allowed,
    raise_called_process_error,
)
from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.log import ASH_LOGGER

# Pattern for safe git revision values: alphanumeric, dots, hyphens, underscores, forward slashes
_SAFE_REVISION_PATTERN = re.compile(r"^[A-Za-z0-9._\-/]+$")
#: A UID or GID as the build and the runner read one.
_ASCII_DIGITS = re.compile(r"[0-9]+")

# Discovery order for OCI runners (first found wins)
_OCI_RUNNER_CANDIDATES = ["finch", "docker", "nerdctl", "podman"]

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
    return _SAFE_REVISION_PATTERN.match(revision) is not None


# ---------------------------------------------------------------------------
# Refusals: results that never reached a container
# ---------------------------------------------------------------------------

#: Set on a result run_ash_container returns before any container ran.
_NOT_STARTED_ATTR = "ash_container_not_started"


def _not_started(result):
    """Mark ``result`` as a refusal: run_ash_container stopped before the run phase.

    The refusals (no runner, a non-numeric UID or GID, an unsafe revision, a missing
    Dockerfile, a failed build, an unusable source or output directory) come back as a
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
    """The directory a full clone would put this package in, whether or not it is one."""
    return Path(__file__).parent.parent.parent


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


def _direct_url_json_path() -> Path:
    """Where the installer recorded the source of this package (PEP 610)."""
    mod = import_module("automated_security_helper")
    return Path(mod.__path__[0] + "-" + mod.__version__ + ".dist-info").joinpath(
        "direct_url.json"
    )


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
            "ASH installation appears to be alongide the repository contents, building with LOCAL source"
        )
        return "LOCAL"

    direct_url_json_path = _direct_url_json_path()
    if direct_url_json_path.exists():
        if not quiet:
            print(
                f"Found direct_url.json file for module @ {direct_url_json_path.as_posix()}"
            )
        try:
            direct_url_json = json.loads(direct_url_json_path.read_text())
            if isinstance(direct_url_json, dict) and "url" in direct_url_json:
                url = direct_url_json["url"]
                if url.startswith("file://"):
                    info(
                        "ASH installed from local file path, building with LOCAL source"
                    )
                    return "LOCAL"
                elif "vcs_info" in direct_url_json and isinstance(
                    direct_url_json["vcs_info"], dict
                ):
                    vcs_info = direct_url_json["vcs_info"]
                    revision = (
                        vcs_info.get("requested_revision")
                        or vcs_info.get("commit_id")
                        or ASH_REPO_LATEST_REVISION
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
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            warning(
                f"Failed to parse direct_url.json: {e}, falling back to latest revision"
            )
            return_val = ASH_REPO_LATEST_REVISION
    else:
        return_val = ASH_REPO_LATEST_REVISION

    return return_val


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

    # Check if the path exists
    if not abs_path.exists():
        raise ValueError(f"Path does not exist: {abs_path}")

    return abs_path


def run_cmd_direct(cmd_list, check=True, debug=False, shell=False, env=None):
    """
    Run a command and stream output directly to console without Rich panels.

    Args:
        cmd_list: List of command arguments
        check: Whether to check the return code
        debug: Whether to print debug information
        env: The command's environment, or None for this process's

    Returns:
        subprocess.CompletedProcess: The result of the command
    """
    # Filter out empty or None values
    cmd_list = [str(item) for item in cmd_list if item is not None]

    # Log the command for debugging
    if debug:
        print(f"Running command: {' '.join(shlex.quote(arg) for arg in cmd_list)}")

    # Create process using subprocess_utils
    process = subprocess_utils.create_process_with_pipes(  # nosec B604 - Args for this command are evaluated for security prior to this internal method being invoked
        args=cmd_list,
        env=env,
        text=True,
        shell=shell,
    )

    # Create buffers for stdout and stderr
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()

    # Function to read from a pipe and stream output
    def read_pipe(pipe, is_stderr=False):
        buffer = stderr_buffer if is_stderr else stdout_buffer
        try:
            for line in iter(pipe.readline, ""):
                buffer.write(line)
                # Print directly to console
                print(line, end="", file=sys.stderr if is_stderr else sys.stdout)
        except Exception as e:
            error_msg = f"Error reading {'stderr' if is_stderr else 'stdout'}: {str(e)}"
            print(error_msg, file=sys.stderr)

    # Create threads to read stdout and stderr
    stdout_thread = threading.Thread(target=read_pipe, args=(process.stdout, False))
    stderr_thread = threading.Thread(target=read_pipe, args=(process.stderr, True))

    # Mark as daemon threads so they don't block program exit
    stdout_thread.daemon = True
    stderr_thread.daemon = True

    # Start threads
    stdout_thread.start()
    stderr_thread.start()

    # Wait for process to complete
    try:
        while process.poll() is None:
            time.sleep(0.1)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully: terminate, wait, then escalate to kill
        process.terminate()
        try:
            process.wait(timeout=5)
        except Exception:
            process.kill()
            process.wait()
        print("Command interrupted by user", file=sys.stderr)

    # Join threads before reading buffers to avoid race condition
    stdout_thread.join(timeout=5.0)
    stderr_thread.join(timeout=5.0)

    # Get the captured output (safe now that threads are joined)
    stdout = stdout_buffer.getvalue()
    stderr = stderr_buffer.getvalue()

    # Create a CompletedProcess object
    result = create_completed_process(
        args=cmd_list,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
    )

    # Check return code if requested
    if check and result.returncode != 0:
        raise_called_process_error(
            returncode=result.returncode,
            cmd=cmd_list,
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


def _resolve_oci_runner(oci_runner: str | None) -> str:
    """Discover and return the path to an OCI runner.

    Args:
        oci_runner: Explicit runner name to use, or None to auto-discover.

    Returns:
        The resolved path to the OCI runner binary.

    Raises:
        RuntimeError: When no runner is found.
    """
    candidates = [oci_runner] if oci_runner else _OCI_RUNNER_CANDIDATES
    for runner in candidates:
        path = _find_runner(runner)
        if path:
            ASH_LOGGER.info(f"Resolved OCI_RUNNER to: {path}")
            return path
    raise RuntimeError("Unable to resolve an OCI runner")


def _get_oci_wrapper_prefix() -> List[str]:
    """Return the OCI_RUNNER_WRAPPER as a list suitable for command prefix."""
    oci_wrapper = os.environ.get("OCI_RUNNER_WRAPPER", "").strip()
    return shlex.split(oci_wrapper) if oci_wrapper else []


def _recorded_source_tree() -> Path | None:
    """The local directory the installer recorded this package was built from, if any.

    pip and uv write ``direct_url.json`` (PEP 610) for an install from a URL. A
    ``file://`` URL with ``dir_info`` is an install from a directory (``pip install
    <dir>``, ``uvx --from <dir>``); one naming an archive or a wheel is not a source
    tree, and neither is a directory that has since lost its Dockerfile.
    """
    try:
        direct_url = json.loads(_direct_url_json_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, AttributeError, TypeError):
        return None
    if not isinstance(direct_url, dict) or "dir_info" not in direct_url:
        return None
    url = direct_url.get("url")
    if not isinstance(url, str) or not url.startswith("file://"):
        return None
    tree = Path(url2pathname(urlparse(url).path))
    if not tree.joinpath("Dockerfile").is_file():
        return None
    return tree


def _local_source_tree() -> Path:
    """The ASH source tree a LOCAL revision builds: its Dockerfile and its context.

    Found from the running package, never from the working directory: the working
    directory is usually the project being scanned, and a Dockerfile there is that
    project's. A clone the package runs from (an editable install) comes first,
    then the directory the installer recorded.

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
    raise FileNotFoundError(
        "Dockerfile not found: a LOCAL revision builds the ASH source tree this ASH "
        f"was installed from, and this installation ({checkout.as_posix()}) has none "
        "beside it or recorded for it. Build a released revision instead "
        "(--ash-revision-to-install <tag>), reinstall ASH from its source directory, "
        "or pass --no-build to run an image you already have."
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
    if int(container_uid) == 0:
        return (
            "The non-root image stage creates a user with UID 0, which is root: ASH "
            "is running as root, or --container-uid 0 was given. Pass --build-target "
            "ci to build the image that runs as root. Another --container-uid and "
            "--container-gid work only when the output directory is writable by that "
            "UID: the container runs as that user and writes its reports there."
        )
    if int(container_gid) == 0:
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
    """
    if resolved_oci_runner in _BUILDX_SUPPORT_CACHE:
        return _BUILDX_SUPPORT_CACHE[resolved_oci_runner]

    supported = False
    try:
        result = subprocess_utils.run_command(
            [resolved_oci_runner, "buildx", "version"],
            capture_output=True,
            check=False,
            log_level=logging.DEBUG,
            timeout=30,
        )
        supported = result.returncode == 0
    except (OSError, SubprocessError) as e:
        # run_command with check=False already converts a timeout or a missing
        # binary into a non-zero CompletedProcess, so this is belt and braces.
        ASH_LOGGER.debug(f"buildx probe for {resolved_oci_runner} failed: {e}")

    if not supported:
        ASH_LOGGER.debug(
            f"{resolved_oci_runner} does not provide buildx -- skipping layer cache"
        )
    _BUILDX_SUPPORT_CACHE[resolved_oci_runner] = supported
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
    typer.echo(
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
            "--build-arg",
            f"BUILD_DATE_EPOCH={int(datetime.now().timestamp())}",
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
    # two do not meet in CI. If both were set by hand, the verified layout wins, since it names
    # content the override would have to fetch.
    base_layout_args = _base_oci_layout_args(
        resolved_oci_runner, buildx=bool(cache_args)
    )
    base_image_override = os.environ.get("ASH_BASE_IMAGE_OVERRIDE", "").strip()
    if base_layout_args:
        typer.echo(
            "Base image taken from the verified OCI layout named by ASH_BASE_OCI_LAYOUT, "
            "with no registry call."
        )
        build_cmd.extend(base_layout_args)
    elif base_image_override:
        typer.echo(
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
        print(f"Running build command: {' '.join(str(a) for a in build_cmd)}")

    result = run_cmd_direct(build_cmd, debug=debug)

    if debug:
        print(f"Build completed with return code: {result.returncode}")


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
    if stage is None:
        return None
    try:
        text = Path(custom_containerfile).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None  # the build reports a file it cannot read
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
) -> str:
    """Build a custom image layered on top of the base ASH image.

    Args:
        base_image_name: Name of the base image to build on top of.
        custom_containerfile: Path to the custom Containerfile/Dockerfile.
        target: The custom file's stage to build, or None for the whole file.

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
    if quiet:
        custom_build_cmd.append("-q")
    custom_build_cmd.append(Path(custom_containerfile).parent.as_posix())

    result = run_cmd_direct(custom_build_cmd, debug=debug)

    if debug:
        print(f"Custom build completed with return code: {result.returncode}")

    return "automated-security-helper:custom"


#: Where a config file kept outside the scanned tree is mounted, read-only.
CONTAINER_CONFIG_ROOT = "/ash-config"
#: Where workspace mode mounts the operator's ``--config``: the same place, with
#: each base it extends where the file that extends it names it.
OPERATOR_CONFIG_MOUNT = CONTAINER_CONFIG_ROOT
#: The same for a workspace policy file kept outside the workspace root.
CONTAINER_WORKSPACE_CONFIG_ROOT = "/ash-workspace-config"


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


def _scanned_tree_roots(source_dir: Path) -> List[Path]:
    """The scanned tree, under every name it has.

    The outermost git checkout holding the source directory, by its own and its
    resolved path, and the source directory's own names (as given, resolved, and
    through ``$PWD``): ``config/sandbox_grants.scanned_checkouts`` and
    ``scan_root_names``, the roots ``sandbox_grants.in_tree_reason`` judges by.
    """
    from automated_security_helper.config.sandbox_grants import (
        scan_root_names,
        scanned_checkouts,
    )

    return [*scanned_checkouts(Path(source_dir)), *scan_root_names(Path(source_dir))]


def _refuse_config_linked_out_of_the_tree(
    config: str, source_dir: Path, label: str = "config file"
) -> None:
    """Refuse a file named inside the scanned tree whose real path is outside it.

    The scanned tree is the outermost checkout at or above the source directory (the
    workspace root, in workspace mode), and the source directory itself
    (``_scanned_tree_roots``). A config or workspace policy path inside it is mounted
    only when its real path, every link on the way resolved, is inside it too; a link
    that stays inside the tree is followed. A path outside the tree is followed
    wherever it points.
    """
    from automated_security_helper.config.sandbox_grants import is_within

    named = Path(os.path.abspath(config))
    trees = _scanned_tree_roots(Path(source_dir))
    if not any(named.is_relative_to(tree) for tree in trees):
        return
    resolved = Path(config).resolve()
    if any(is_within(resolved, tree) for tree in trees):
        return
    raise ContainerInputError(
        f"The {label} {config!r} is inside the scanned tree but is a link, or "
        f"is reached through one, to {resolved}, which is outside it. ASH does not "
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

    pending = [Path(config).resolve()]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            refs = _extends_refs_of(current)
        except Exception:  # the scan inside reports why it cannot be read
            continue
        for ref in refs:
            if Path(ref).is_absolute() or Path(ref).drive:
                raise ContainerInputError(
                    f"'{EXTENDS_KEY}: {ref}' in {current} names a base by absolute "
                    "path, which does not name the same file inside the container: "
                    "the config and the files it extends are mounted at their place "
                    "relative to the config. Write the base relative to the file "
                    "that extends it."
                )
            pending.append((current.parent / ref).resolve())


def _require_mountable(label: str, path: Path | str) -> None:
    """Refuse a path the runner would read as something other than that path."""
    text = str(path)
    if any(character in text for character in _UNMOUNTABLE_CHARACTERS):
        raise UnmountablePathError(
            f"The {label} {text!r} cannot be handed to the container runner: --mount "
            "reads its value as comma-separated fields, so a path holding a comma, a "
            "double quote or a line break would be read as something else. Rename it, "
            "or choose another path."
        )


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
    if source == output or source.is_relative_to(output):
        raise ContainerInputError(
            f"The output directory {output} is the source directory {source} or a "
            "directory above it. Container mode mounts the output read-write at "
            "/out and the source read-only at /src, so the source would be "
            "writable through /out. Use an output directory inside the source "
            "(the default .ash/ash_output) or outside it, not above it."
        )


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


def _require_mountable_inputs(
    source_dir: Path | str,
    output_dir: Path | str,
    config: str | None,
    workspace_config: str | None,
    workspace_relative_file: str | None,
) -> None:
    """Check every host path a run would mount, before anything is built or run."""
    source = Path(source_dir).resolve()
    _require_mountable("source directory", source)
    _require_mountable("output directory", Path(output_dir).resolve())
    _refuse_unusable_output_dir(source_dir, output_dir)
    if config:
        _refuse_config_linked_out_of_the_tree(config, source)
        _refuse_absolute_extends(config)
        _, _, config_files = _host_file_in_container(
            config, source, CONTAINER_CONFIG_ROOT, follow_extends=True
        )
        if workspace_relative_file is not None:
            _refuse_repository_config_in_a_workspace(config, config_files, source)
    if workspace_config and workspace_relative_file is not None:
        _refuse_config_linked_out_of_the_tree(
            workspace_config, source, "workspace policy"
        )
        _host_file_in_container(
            workspace_config,
            source,
            CONTAINER_WORKSPACE_CONFIG_ROOT,
            follow_extends=False,
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
    if not config or not Path(config).is_file():
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


def container_input_refusal(
    source_dir: Path | str,
    output_dir: Path | str,
    config: str | None,
    workspace_config: str | None = None,
    workspace_relative_file: str | None = None,
) -> str | None:
    """Why a container scan cannot be given its inputs as they are, or None.

    The config file (:func:`_unreadable_config`) and every host path the run would
    mount (:func:`_require_mountable_inputs`). A refusal is exit 3, the code a local
    scan gives an unusable config. ``run_ash_container`` checks this before it
    builds anything; ``run_ash_scan`` checks it before it clears the previous run's
    output, so a refused scan leaves that output as it was.
    """
    refusal = _unreadable_config(config)
    if refusal is not None:
        return refusal
    try:
        _require_mountable_inputs(
            source_dir, output_dir, config, workspace_config, workspace_relative_file
        )
    except ContainerInputError as e:
        return str(e)
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


#: Tells the scan inside the container that its --config was written by the
#: repository being scanned, with every file it extends; see _config_marks.
CONFIG_FROM_SCANNED_REPOSITORY_FLAG = "--config-from-scanned-repository"
#: Tells the scan inside the container that one file the --config extends was
#: written by the repository being scanned, by its container path; see _config_marks.
CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG = "--config-file-from-scanned-repository"


def _config_marks(config: str, source_dir: Path) -> Tuple[bool, List[str]]:
    """Which mounted config files a local scan of *source_dir* would count as
    repository-written: (the --config itself, the container paths of the files it
    extends that are).

    The same rule ``resolve_config`` applies to a local scan,
    ``config/sandbox_grants.untrusted_path``, to each file by its resolved path and
    by the names that reached it (the --config as the operator named it, and each
    base as its extends entry spells it): a file inside any git checkout or the
    source directory, or reached through a link inside one. The files are mounted
    at /ash-config, outside the scan's own tree inside the container, so the host
    decides and tells it: the whole chain with CONFIG_FROM_SCANNED_REPOSITORY_FLAG
    when the --config is repository-written, else each base that is with
    CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG, so the --config keeps the sandbox
    settings it writes itself, as it does on the host. A config inside the source
    directory is read through /src and needs neither.
    """
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        resolve_config_document,
    )
    from automated_security_helper.config.sandbox_grants import untrusted_path

    source = Path(source_dir)
    resolved = Path(config).resolve()
    if resolved.is_relative_to(source.resolve()):
        return False, []
    if untrusted_path(resolved, source) or untrusted_path(Path(config), source):
        return True, []
    root = default_confinement_root(resolved, source.resolve())
    inner_config = f"{CONTAINER_CONFIG_ROOT}/{resolved.relative_to(root).as_posix()}"
    try:
        document = resolve_config_document(resolved, confine_to=root)
        placements = _chain_placements(resolved, inner_config, CONTAINER_CONFIG_ROOT)
    except Exception:  # noqa: BLE001 - mounted alone; the scan inside reports it
        return False, []
    names: dict = {}
    for file, name in zip(document.chain, document.named):
        names.setdefault(Path(file), []).append(Path(name))
    marked = [
        inner
        for file, inner in placements[1:]
        if untrusted_path(file, source)
        or any(untrusted_path(name, source) for name in names.get(file, []))
    ]
    return False, sorted(set(marked))


def _refuse_repository_config_in_a_workspace(
    config: str, config_files: List[Path], source_dir: Path
) -> None:
    """Refuse, in workspace mode, a mounted config from the workspace's own checkout.

    *source_dir* is the workspace root. A config mounted from another git checkout
    is marked with CONFIG_FROM_SCANNED_REPOSITORY_FLAG, as in a one-directory scan,
    and the workspace scan inside limits it for every project
    (``sandbox_grants.marked_repository_written``). One in the checkout around the
    workspace root, or reached through a link there (``sandbox_grants.in_tree_reason``),
    is the scanned repository's own file outside the tree the scan inside sees, and
    is refused instead, whichever file of its chain makes it so, before anything is
    built or mounted. ``run_ash_scan`` refuses it before this as well, with
    ``resolve_config.check_operator_config``'s message, which a caller of this
    module does not run. A config inside the workspace root mounts no file of its
    own: it is read through /src, and refused as in a local workspace scan, because
    the operator's config may not be one of the workspace's files. One outside
    every checkout is the operator's.
    """
    from automated_security_helper.config.sandbox_grants import in_tree_reason

    inside = [
        path
        for path in [*config_files, Path(config)]
        if in_tree_reason(path, Path(source_dir)) is not None
    ]
    if not config_files or not inside:
        return
    raise ContainerInputError(
        f"The config file {config!r} is the scanned repository's: "
        f"{', '.join(path.as_posix() for path in inside)} is in the git checkout "
        "around the workspace root "
        f"{Path(source_dir).as_posix()}, or reached through a link there, and "
        "outside the workspace root, where the workspace scan inside the container "
        "cannot see it. Container mode refuses it in workspace mode. Keep --config, "
        "and every file it extends, outside every git checkout."
    )


def _extends_refs_of(path: Path) -> List[str]:
    """The ``extends`` entries of one config file, as written."""
    from automated_security_helper.config.config_sources import (
        EXTENDS_KEY,
        read_config_file,
    )

    data = read_config_file(path)
    refs = data.get(EXTENDS_KEY) if isinstance(data, dict) else None
    refs = [refs] if isinstance(refs, str) else refs or []
    return [ref.strip() for ref in refs if isinstance(ref, str) and ref.strip()]


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
    from automated_security_helper.config.config_sources import EXTENDS_KEY

    placements: List[Tuple[Path, str]] = []
    placed: dict = {}
    # (host file, its container path, the (extending file, entry) that named it)
    pending: List[Tuple[Path, str, Tuple[Path, str] | None]] = [
        (resolved, destination, None)
    ]
    while pending:
        host_file, inner, named_by = pending.pop()
        if not inner.startswith(mount_root.rstrip("/") + "/"):
            extending, ref = named_by if named_by is not None else (host_file, inner)
            raise ContainerInputError(
                f"'{EXTENDS_KEY}: {ref}' in {extending} names {host_file}, which "
                f"would be mounted at {inner}, outside {mount_root}: inside the "
                "container the entry is followed as written, from where the "
                "extending file is mounted. Name the base by a path below the "
                "config's own directory that does not go through a link to a "
                "directory at another depth."
            )
        if inner in placed:
            if placed[inner] != host_file:
                raise ContainerInputError(
                    f"Two files of the config's extends chain, {placed[inner]} and "
                    f"{host_file}, would both be mounted at {inner}. Name each base "
                    "by its own path."
                )
            continue
        placed[inner] = host_file
        placements.append((host_file, inner))
        for ref in _extends_refs_of(host_file):
            pending.append(
                (
                    (host_file.parent / ref).resolve(),
                    posixpath.normpath(posixpath.join(posixpath.dirname(inner), ref)),
                    (host_file, ref),
                )
            )
    # A file mounted at a path another file of the chain needs as a directory: the
    # runner cannot create both mounts.
    root = mount_root.rstrip("/")
    for inner, host_file in placed.items():
        parent = posixpath.dirname(inner)
        while parent != root and parent.startswith(root + "/"):
            if parent in placed:
                raise ContainerInputError(
                    f"{placed[parent]} would be mounted at {parent}, where "
                    f"{host_file} needs a directory to be mounted at {inner}. Name "
                    "each base by its own path."
                )
            parent = posixpath.dirname(parent)
    return placements


def _refuse_bases_inside_the_source(
    config: Path, bases: List[Tuple[Path, str]], source: Path
) -> None:
    """Refuse a chain kept outside the source directory that extends a file inside it.

    The files of a chain kept outside the source directory are mounted from under
    the outside config's own directory (``config_sources.default_confinement_root``).
    A base inside the source directory is refused, and with it the files that base
    extends: a chain is either read whole through ``/src``, with the config inside
    the source directory, or mounted whole from outside it.
    """
    from automated_security_helper.config.sandbox_grants import is_within

    for base, _ in bases:
        if is_within(base, source):
            raise ContainerInputError(
                f"The config file {config} is outside the source directory {source}, "
                f"but its extends chain includes {base}, which is inside it. ASH does "
                "not mount files a config of the repository being scanned chooses. "
                "Keep the chain outside the repository, or put the config inside the "
                "source directory, where its whole chain stays there too."
            )


def _refuse_repository_bases_reaching_out(
    placements: List[Tuple[Path, str]], source: Path
) -> None:
    """Refuse a chain where a file inside the scanned checkout extends one outside it.

    A file of the chain inside the scanned checkout (``_scanned_tree_roots``) may
    extend only files inside that checkout. Files outside it are mounted when a
    config outside the checkout names them.
    """
    from automated_security_helper.config.sandbox_grants import is_within

    trees = _scanned_tree_roots(source)

    def written_by_the_repository(path: Path) -> bool:
        return any(is_within(path, tree) for tree in trees)

    for file, _ in placements:
        if not written_by_the_repository(file):
            continue
        for ref in _extends_refs_of(file):
            base = (file.parent / ref).resolve()
            if not written_by_the_repository(base):
                raise ContainerInputError(
                    f"{file} is in the repository being scanned and extends {base}, "
                    "which is outside it. ASH does not mount files a config of the "
                    "repository being scanned chooses. Extend that file from a config "
                    "outside the repository instead."
                )


def _host_file_in_container(
    host_path: str, source_dir: Path, mount_root: str, *, follow_extends: bool
) -> Tuple[List[str], str, List[Path]]:
    """The mounts that make a host config file readable in the container, its path
    there, and the host files those mounts are of.

    A file inside the source directory is already under the read-only ``/src``
    mount, and so is every ``extends`` base it can name: a config inside the
    source directory is confined to it (``config_sources.default_confinement_root``).

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
    """
    resolved = Path(host_path).resolve()
    source = Path(source_dir).resolve()
    if resolved.is_relative_to(source):
        return [], f"/src/{resolved.relative_to(source).as_posix()}", []

    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        resolve_config_document,
    )

    root = default_confinement_root(resolved, source)
    inner_config = f"{mount_root}/{resolved.relative_to(root).as_posix()}"
    placements = [(resolved, inner_config)]
    if follow_extends:
        try:
            # Validated as the scan will validate it (confinement, bounds, cycles)
            # before anything is placed.
            resolve_config_document(resolved, confine_to=root)
            placements = _chain_placements(resolved, inner_config, mount_root)
            _refuse_bases_inside_the_source(resolved, placements[1:], source)
            _refuse_repository_bases_reaching_out(placements, source)
        except ContainerInputError:
            raise
        except Exception as e:
            # See the docstring: the scan inside reports it.
            ASH_LOGGER.debug(
                f"Mounting {resolved} alone: its chain did not resolve: {e}"
            )

    mounts: List[str] = []
    for file, destination in placements:
        _require_mountable("config file", file)
        # The container path is the extends entry as written, which can hold the
        # character through a link's name while the file's own path does not.
        _require_mountable("container path of a config file", destination)
        mounts.extend(
            ["--mount", f"type=bind,source={file},destination={destination},readonly"]
        )
    return mounts, inner_config, list(dict.fromkeys(file for file, _ in placements))


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
    log_level: AshLogLevel | str | None = None,
    outer_run_id: str | None = None,
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
        config: The host path of ``--config``. It is made readable in the
            container and the inner scan is given the path it has there; see
            :func:`_host_file_in_container`.
        workspace_config: In workspace mode, the host path of the workspace
            policy the host resolved, handed over the same way as
            ``--workspace-config``.
        outer_run_id: Handed to the in-container run, which writes it into its
            results file when it completes (utils/inner_run_outcome.py).
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

    cmd: List[str] = [*oci_command_prefix, resolved_oci_runner, "run", "--rm"]

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
    if config:
        _refuse_config_linked_out_of_the_tree(config, source_dir)
        _refuse_absolute_extends(config)
        config_mounts, inner_config, config_files = _host_file_in_container(
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
            _refuse_repository_config_in_a_workspace(config, config_files, source_dir)
        if config_files:
            config_from_scanned_repository, marked_config_files = _config_marks(
                config, source_dir
            )
    inner_workspace_config = None
    if workspace_config and workspace_relative_file is not None:
        _refuse_config_linked_out_of_the_tree(
            workspace_config, source_dir, "workspace policy"
        )
        policy_mounts, inner_workspace_config, _ = _host_file_in_container(
            workspace_config,
            source_dir,
            CONTAINER_WORKSPACE_CONFIG_ROOT,
            follow_extends=False,
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

    if inner_config is not None:
        ash_args.extend(["--config", inner_config])
    if config_from_scanned_repository:
        ash_args.append(CONFIG_FROM_SCANNED_REPOSITORY_FLAG)
    for marked in marked_config_files:
        ash_args.extend([CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG, marked])

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
        # Worse, a usage error exits 2, which is also ASH's code for actionable findings,
        # so the host's read-back could not tell the rejected invocation from a dirty scan.
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
    typer.echo("Running ASH scan using built image...")
    if debug:
        print(f"Running container command: {' '.join(str(a) for a in cmd)}")
    try:
        result = run_cmd_direct(cmd, debug=debug, env=env)
        if debug:
            print(
                f"Container execution completed with return code: {result.returncode}"
            )
        return result
    except CalledProcessError as e:
        if debug:
            print(f"Container execution failed with error: {e}")
        return e


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
    outer_run_id: str | None = None,
):
    """Build and run the ASH container image.

    Args:
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
    # runner cannot mount, is not worth one.
    config_refusal = (
        container_input_refusal(
            source_dir, output_dir, config, workspace_config, workspace_relative_file
        )
        if run
        else None
    )
    if config_refusal is not None:
        typer.secho(config_refusal, fg=typer.colors.RED)
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
        typer.secho(f"Error getting user ID information: {e}", fg=typer.colors.RED)
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
        typer.secho(message, fg=typer.colors.RED)
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
        typer.secho(str(e), fg=typer.colors.RED)
        return _not_started(
            create_completed_process(args=[], returncode=1, stdout="", stderr=str(e))
        )

    oci_command_prefix = _get_oci_wrapper_prefix()

    # Resolve ASH revision. One given was checked above (container_build_refusal);
    # the one derived from this installation is checked here.
    rev = get_ash_revision()
    resolved_revision = (
        ash_revision_to_install if ash_revision_to_install is not None else rev
    )

    if resolved_revision is not None and resolved_revision != "LOCAL":
        if not _validate_ash_revision(resolved_revision):
            message = _invalid_revision_message(resolved_revision)
            typer.secho(message, fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=message
                )
            )

    resolved_build_target = _resolve_build_target(build_target, custom_containerfile)
    ash_base_image_name = os.environ.get(
        "ASH_IMAGE_NAME", f"automated-security-helper:{resolved_build_target}"
    )

    # Build phase (a non-root build as UID or GID 0 was refused above)
    if build:
        # Only a build reads the Dockerfile. --no-build runs an image that is already
        # present, so looking one up first refused a scan outside an ASH checkout
        # (revision LOCAL, no Dockerfile in or above the working directory) although
        # nothing was going to be built.
        try:
            dockerfile_path = _find_dockerfile(resolved_revision)
        except FileNotFoundError as e:
            typer.secho(str(e), fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )
            )

        try:
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
                )

        except Exception as e:
            typer.secho(f"Error building ASH image: {e}", fg=typer.colors.RED)
            if debug:
                if hasattr(e, "stdout"):
                    print(f"Build stdout: {e.stdout}")
                if hasattr(e, "stderr"):
                    print(f"Build stderr: {e.stderr}")
            if isinstance(e, CalledProcessError):
                return _not_started(e)
            return _not_started(
                create_completed_process(
                    args=[], returncode=1, stdout="", stderr=str(e)
                )
            )

    # Run phase
    if run:
        if source_dir:
            try:
                source_dir = validate_path(source_dir)
            except ValueError as e:
                typer.secho(str(e), fg=typer.colors.RED)
                return _not_started(
                    create_completed_process(
                        args=[], returncode=1, stdout="", stderr=str(e)
                    )
                )

        if not source_dir:
            source_dir = Path.cwd()
            ASH_LOGGER.info(f"Using current directory as source: {source_dir}")

        if output_dir:
            try:
                output_dir = Path(output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)
                output_dir = output_dir.resolve()
            except Exception as e:
                typer.secho(
                    f"Error creating output directory: {e}", fg=typer.colors.RED
                )
                return _not_started(
                    create_completed_process(
                        args=[], returncode=1, stdout="", stderr=str(e)
                    )
                )
        else:
            output_dir = source_dir.joinpath("ash_output")
            output_dir.mkdir(parents=True, exist_ok=True)
            ASH_LOGGER.info(f"Using default output directory: {output_dir}")

        try:
            run_cmd = _assemble_run_command(
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
                log_level=log_level,
                outer_run_id=outer_run_id,
            )
        except ContainerInputError as e:
            # Checked before the build already; this catches a path that only
            # became unmountable once resolved here.
            typer.secho(str(e), fg=typer.colors.RED)
            return _not_started(
                create_completed_process(
                    args=[], returncode=3, stdout="", stderr=str(e)
                )
            )

        return _execute_container(
            run_cmd, debug=debug, env=_run_environment(outer_run_id)
        )

    # Built but not run
    return create_completed_process(args=[], returncode=0, stdout="", stderr="")
