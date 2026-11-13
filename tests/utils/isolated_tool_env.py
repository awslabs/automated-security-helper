# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An environment for a test subprocess that runs ASH and must write nothing outside its temp dir.

Listing scanners and building scan tasks probe, and when a tool is missing install,
each uv-managed scanner, even for scanners a scan excludes; checkov keeps an update
cache; and HOME alone does not move uv's directories when the XDG variables are set.
So a subprocess built with these helpers gets:

* every directory a tool or installer writes to (XDG cache, data, config and bin
  directories, ``UV_TOOL_DIR``, ``UV_TOOL_BIN_DIR``, ``ASH_BIN_PATH``) under *root*;
* ``UV_OFFLINE=1`` and HTTP(S) proxies that refuse every connection, so nothing is
  fetched;
* no usable AWS settings: the config and credentials files are the null device,
  instance metadata is off, and every AWS endpoint is a port that refuses
  connections (:data:`AWS_SETTINGS`). The harness drops the AWS variables it
  inherited first (:func:`without_inherited_aws`), because an inherited
  ``AWS_PROFILE`` or access key would still apply;
* ``UV_CACHE_DIR`` taken from the caller's environment when it is set, so a cache the
  operator chose is read rather than refilled, and otherwise an empty cache under
  *root*. The offline, proxy, AWS and cache settings are :func:`network_containment`,
  which a harness that builds its own child environment applies too;
* stub ``uv``, ``gem`` and ``npm`` executables, put first on PATH with
  :func:`install_refusing_installers`, which exit non-zero without installing
  anything.

HOME and USERPROFILE are left alone: tests/conftest.py already points both at a
private directory for the whole session (see "The session HOME" there).
"""

from __future__ import annotations

import contextlib
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Mapping

#: A port nothing listens on, so a proxied connection is refused at once.
REFUSING_PROXY = "http://127.0.0.1:9"

#: AWS settings that give an in-process scan no credentials and no reachable
#: endpoint, whatever the host has configured.
AWS_SETTINGS = {
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    "AWS_EC2_METADATA_DISABLED": "true",
    "AWS_ENDPOINT_URL": REFUSING_PROXY,
    "AWS_REGION": "us-east-1",
}


def without_inherited_aws(env: Mapping[str, str]) -> Dict[str, str]:
    """*env* without any ``AWS_*`` variable, for a harness to apply its own on top."""
    return {key: value for key, value in env.items() if not key.startswith("AWS_")}


#: The proxy variables an HTTP client reads, set in both cases.
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")

#: The hosts a contained child may reach without the refusing proxy: the loopback
#: names, for the local servers a test starts (moto). Nothing outside this machine.
LOOPBACK_NO_PROXY = "localhost,127.0.0.1,::1"


def refusing_proxies(no_proxy: str = LOOPBACK_NO_PROXY) -> Dict[str, str]:
    """Every proxy variable, in both cases, on a port that refuses the connection,
    and ``NO_PROXY`` naming only ``no_proxy``'s hosts."""
    env = {}
    for name in PROXY_VARIABLES:
        env[name] = REFUSING_PROXY
        env[name.lower()] = REFUSING_PROXY
    env["NO_PROXY"] = no_proxy
    env["no_proxy"] = no_proxy
    return env


def _no_proxy_stays_local(value: str) -> bool:
    hosts = [host.strip().lower() for host in value.split(",") if host.strip()]
    return all(host in LOOPBACK_NO_PROXY.split(",") for host in hosts)


#: What turns off the version and update checks a scanner makes on any run,
#: ``--version`` included: semgrep's semgrep.dev version check and metrics, and
#: checkov's package-index update check. opengrep makes neither. tests/conftest.py
#: sets these for the whole session too, for the children an in-process scan starts.
SCANNER_UPDATE_CHECKS_OFF = {
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "SEMGREP_SEND_METRICS": "off",
    "CKV_SKIP_PACKAGE_UPDATE_CHECK": "true",
}


def network_containment(environ: Mapping[str, str] = os.environ) -> Dict[str, str]:
    """The variables that keep a test's child process off the network.

    Applied last, over whatever else a child's environment holds, by every helper
    that builds one, whether it starts from a filtered copy of *environ* or from
    nothing: a filter that drops ``UV_*`` or ``AWS_*`` drops the caller's own
    settings for these too.

    * ``UV_OFFLINE=1``, with ``UV_CACHE_DIR`` the caller's (made absolute) when
      *environ* sets one, so uv reads the run's own cache and fetches nothing;
    * every HTTP(S) proxy a port that refuses the connection, with ``NO_PROXY``
      empty, so no other client gets out either;
    * :data:`AWS_SETTINGS`: no credentials file, no config file, no instance
      metadata, and an endpoint that refuses. A helper that starts from *environ*
      drops the inherited ``AWS_*`` variables first (:func:`without_inherited_aws`),
      because an inherited access key or profile would still apply;
    * :data:`SCANNER_UPDATE_CHECKS_OFF`: a scanner the child starts makes no
      version or update check of its own.
    """
    env: Dict[str, str] = {"UV_OFFLINE": "1"}
    cache = environ.get("UV_CACHE_DIR")
    if cache:
        env["UV_CACHE_DIR"] = str(Path(cache).absolute())
    env.update(refusing_proxies(no_proxy=""))
    env.update(AWS_SETTINGS)
    env.update(SCANNER_UPDATE_CHECKS_OFF)
    return env


def network_uncontained(env: Mapping[str, str]) -> List[str]:
    """What *env* lacks of the offline uv and refusing proxies, by name, or [].
    ``NO_PROXY`` may name the loopback hosts and nothing else. Values are not
    quoted: a host's proxy setting can hold credentials."""
    missing = missing_proxies(env)
    if env.get("UV_OFFLINE") != "1":
        missing.append("UV_OFFLINE=1")
    return missing


class ChildRunStopped(Exception):
    """Raised in place of a child's start by :func:`env_of_child_run`."""


def env_of_child_run(call: Callable[[], object]) -> Dict[str, str]:
    """The environment *call* gives the child it starts with ``subprocess.run``,
    read without starting it.

    The first ``subprocess.run`` inside *call* raises :class:`ChildRunStopped`
    instead of starting anything, and the environment is the one it was handed:
    its ``env=``, else this process's own, which a child inherits.
    """
    import subprocess  # nosec B404 - replaced, never run
    from unittest import mock

    seen: Dict[str, str] = {}

    def stop(*_args: object, **kwargs: object) -> None:
        env = kwargs.get("env")
        seen.update(env if isinstance(env, Mapping) else os.environ)
        raise ChildRunStopped

    with mock.patch.object(subprocess, "run", stop):
        try:
            call()
        except ChildRunStopped:
            return seen
    raise AssertionError("the call started no child with subprocess.run")


#: The containment a test's child process must carry: what
#: :func:`network_containment` sets, less the proxies, which a child that talks
#: to a local server leaves out. The real-program guard
#: (tests/utils/no_real_programs.py) checks it with :func:`missing_containment`.
CONTAINMENT_KEYS = (
    "UV_OFFLINE",
    "UV_CACHE_DIR",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_ENDPOINT_URL",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
)

#: Hosts an AWS endpoint may name and still reach nothing outside this machine:
#: the loopback names, and the ``.invalid`` top-level domain, which never
#: resolves (RFC 6761).
_LOCAL_HOSTS = ("localhost", "::1")


def _endpoint_stays_local(url: str) -> bool:
    import ipaddress
    from urllib.parse import urlsplit

    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if host in _LOCAL_HOSTS or host.endswith(".invalid") or host == "invalid":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _names_no_credentials(path: str) -> bool:
    """The null device, a file that does not exist, or an empty file: nothing to
    read keys from."""
    if path == os.devnull:
        return True
    candidate = Path(path)
    if not candidate.exists():
        return True
    try:
        return candidate.is_file() and candidate.stat().st_size == 0
    except OSError:
        return False


def missing_containment(env: Mapping[str, str]) -> List[str]:
    """The containment keys *env* lacks, each with what it should be, or [].

    *env* is the whole environment a child starts with: its ``env=`` argument,
    or the parent's own when it passes none.

    * ``UV_OFFLINE`` is ``1`` and ``UV_CACHE_DIR`` names a directory, so uv
      fetches nothing;
    * ``AWS_EC2_METADATA_DISABLED`` is ``true``, ``AWS_ENDPOINT_URL`` names a
      loopback or ``.invalid`` host (a local moto server counts), and
      ``AWS_CONFIG_FILE`` and ``AWS_SHARED_CREDENTIALS_FILE`` are the null device
      or a file that does not exist, so an AWS call has no credentials and no
      reachable endpoint.
    """
    return list(_uncontained(env).values())


def missing_proxies(env: Mapping[str, str]) -> List[str]:
    """The proxy settings *env* does not satisfy, each with what it should be,
    or []: every variable in :data:`PROXY_VARIABLES`, in both cases, names the
    port that refuses the connection, and ``NO_PROXY`` names no host but the
    loopback ones, so no client gets out. Values are not quoted: a host's proxy
    setting can hold credentials."""
    missing = [
        f"{key}={REFUSING_PROXY}"
        for name in PROXY_VARIABLES
        for key in (name, name.lower())
        if env.get(key) != REFUSING_PROXY
    ]
    missing += [
        f"{key} naming no host but {LOOPBACK_NO_PROXY}"
        for key in ("NO_PROXY", "no_proxy")
        if not _no_proxy_stays_local(env.get(key, ""))
    ]
    return missing


def _uncontained(env: Mapping[str, str]) -> Dict[str, str]:
    """Each containment key *env* does not satisfy, with what it should be."""
    missing: Dict[str, str] = {}
    if str(env.get("UV_OFFLINE", "")).strip().lower() not in ("1", "true", "yes"):
        missing["UV_OFFLINE"] = "UV_OFFLINE=1"
    if not env.get("UV_CACHE_DIR"):
        missing["UV_CACHE_DIR"] = "UV_CACHE_DIR (the run's own cache)"
    if str(env.get("AWS_EC2_METADATA_DISABLED", "")).strip().lower() != "true":
        missing["AWS_EC2_METADATA_DISABLED"] = "AWS_EC2_METADATA_DISABLED=true"
    endpoint = env.get("AWS_ENDPOINT_URL")
    if not endpoint or not _endpoint_stays_local(endpoint):
        missing["AWS_ENDPOINT_URL"] = "AWS_ENDPOINT_URL on a loopback or .invalid host"
    for name in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"):
        value = env.get(name)
        if not value or not _names_no_credentials(value):
            missing[name] = f"{name}={os.devnull}"
    return missing


def session_containment(
    environ: Mapping[str, str], default_cache: Path
) -> Dict[str, str]:
    """The containment set for a test process's own environment, which every child
    started with no ``env=`` inherits.

    ``UV_OFFLINE=1``, ``UV_CACHE_DIR`` the caller's or ``default_cache``, and
    :data:`AWS_SETTINGS`. Not the proxies: a test talks to local servers through
    its own HTTP clients, which would send those requests to the refusing proxy.
    The inherited AWS variables are dropped first; see :func:`contained_session`.
    """
    env = {"UV_OFFLINE": "1"}
    env["UV_CACHE_DIR"] = str(
        Path(environ.get("UV_CACHE_DIR") or default_cache).absolute()
    )
    env.update(AWS_SETTINGS)
    return env


def with_containment(env: Mapping[str, str]) -> Dict[str, str]:
    """*env* with the containment set on top, for a test that builds a child's
    environment from nothing: offline uv with this process's own cache, and the
    AWS settings of :data:`AWS_SETTINGS`, which replace any the test set.

    The real-program guard (tests/utils/no_real_programs.py) admits a script or
    an interpreter only with this set; the guarded test process carries it, so
    its ``UV_CACHE_DIR`` is the one used. Without one, an empty cache under the
    temporary directory.
    """
    import tempfile

    default_cache = Path(tempfile.gettempdir()) / "ash-contained-uv-cache"
    if not os.environ.get("UV_CACHE_DIR"):
        default_cache.mkdir(parents=True, exist_ok=True)
    return {**env, **session_containment(os.environ, default_cache)}


#: The AWS variables this process inherited, with their values, read when this
#: module is first imported: tests/conftest.py imports it (through
#: tests/utils/no_real_programs.py) before any fixture runs.
_INHERITED_AWS = {
    key: value for key, value in os.environ.items() if key.startswith("AWS_")
}


def drop_inherited_aws() -> None:
    """Remove, for the rest of the process, each AWS variable it inherited and
    still holds with the inherited value: a profile or an access key from the
    caller's shell would still apply. A value a fixture set stays. Not undone at
    a module's end, so a session fixture's own values (tests/unit/deploy's fake
    credentials) are never replaced by the inherited ones."""
    for key, value in _INHERITED_AWS.items():
        if os.environ.get(key) == value:
            del os.environ[key]


@contextlib.contextmanager
def contained_session(default_cache: Path) -> Iterator[None]:
    """The test process carries the containment set inside the block.

    The inherited AWS variables are dropped (:func:`drop_inherited_aws`); then each
    containment key the environment does not already satisfy is set from
    :func:`session_containment`, and ``AWS_REGION`` if it is unset. A value that
    already satisfies it (a fixture's moto endpoint, its own missing config
    file) is left as it is. On leaving, a key is put back only if it still holds
    the value set here, so a session-scoped fixture that set its own value in
    the block keeps it.
    """
    drop_inherited_aws()
    wanted = session_containment(os.environ, default_cache)
    keys = set(_uncontained(os.environ))
    if not os.environ.get("AWS_REGION"):
        keys.add("AWS_REGION")
    if "UV_CACHE_DIR" in keys:
        default_cache.mkdir(parents=True, exist_ok=True)
    applied = {key: wanted[key] for key in keys}
    previous = {key: os.environ.get(key) for key in applied}
    os.environ.update(applied)
    try:
        yield
    finally:
        for key, value in applied.items():
            if os.environ.get(key) != value:
                continue
            before = previous[key]
            if before is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = before


#: Installers a scan or a scanner listing can start.
REFUSED_INSTALLERS = ("uv", "gem", "npm")

_TOOL_DIRS = {
    "XDG_CACHE_HOME": "xdg-cache",
    "XDG_DATA_HOME": "xdg-data",
    "XDG_CONFIG_HOME": "xdg-config",
    "XDG_BIN_HOME": "xdg-bin",
    "UV_TOOL_DIR": "uv-tools",
    "UV_TOOL_BIN_DIR": "uv-tool-bin",
    "ASH_BIN_PATH": "ash-bin",
}


def isolated_tool_dirs(root: Path) -> Dict[str, str]:
    """The directory variables alone: where tools and installers write, under *root*.

    For a test that runs scanner code in its own process and sets these with
    ``monkeypatch.setenv``; the proxy and AWS settings of :func:`isolated_tool_env`
    are for a subprocess.
    """
    env: Dict[str, str] = {}
    for name, sub in _TOOL_DIRS.items():
        path = root / sub
        path.mkdir(parents=True, exist_ok=True)
        env[name] = str(path)
    return env


def isolated_tool_env(root: Path) -> Dict[str, str]:
    """Variables that keep a subprocess's tools, caches and downloads under *root*."""
    env: Dict[str, str] = {**isolated_tool_dirs(root), **network_containment()}
    if "UV_CACHE_DIR" not in env:
        cache_dir = root / "uv-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        env["UV_CACHE_DIR"] = str(cache_dir)
    return env


_STUB = (
    "import sys\n"
    "sys.stderr.write('{name} is stubbed in this test and installs nothing\\n')\n"
    "raise SystemExit(1)\n"
)


def install_refusing_installers(
    bin_dir: Path, names: Iterable[str] = REFUSED_INSTALLERS
) -> None:
    """Put a stub for each installer in *bin_dir*, which the harness puts first on PATH.

    An executable launcher on POSIX; a ``.cmd`` shim on Windows, where a shebang script
    cannot be started and executables are found by extension.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        script = bin_dir / f"_stub_{name}.py"
        script.write_text(_STUB.format(name=name), encoding="utf-8")
        if platform.system().lower() == "windows":
            (bin_dir / f"{name}.cmd").write_text(
                f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8"
            )
            continue
        launcher = bin_dir / name
        launcher.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
        )
        launcher.chmod(
            launcher.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        )
