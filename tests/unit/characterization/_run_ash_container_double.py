# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The OCI runtime doubles and the machine the container-mode cells run on.

``test_run_ash_container.py``, ``test_build_image.py`` and the routing cells of
operator paths import these; this module imports no test file. The runtime double
knows ASH's packaged Dockerfile and build context by path and never touches them;
``id`` reports ``HOST_UID`` and ``HOST_GID``; ``_FrozenDatetime`` and ``_Sys`` stand
in for the container module's ``datetime`` and ``sys`` where a cell freezes them.
"""

from __future__ import annotations

import datetime as _datetime
import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from automated_security_helper.interactions import run_ash_container as rac
from tests.unit.characterization._harness import (
    PACKAGE_DIR,
    ArgvGrammar,
    Exit,
    Outcome,
    ToolCall,
    ToolDouble,
)

RUNTIMES = ("finch", "docker", "nerdctl", "podman")

#: The Dockerfile and build context ASH ships in its package, which a build of a
#: revision names. They are outside the test's tree, so the runtime double knows them
#: by path and never touches them; any other --file or context must be in the tree.
PACKAGED_DOCKERFILE = PACKAGE_DIR / "assets" / "Dockerfile"
PACKAGED_CONTEXT = PACKAGE_DIR / "assets"

#: What the frozen ``datetime.now()`` answers: 2026-01-02T03:04:05Z.
FROZEN_NOW = _datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=_datetime.timezone.utc)

#: What the ``id`` double reports.
HOST_UID = "1234"
HOST_GID = "5678"

#: The files a checkout holds: enough of each to be recognizably that file.
CHECKOUT_DOCKERFILE = (
    "# characterization stand-in for the ASH Dockerfile\n"
    "ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.12-bookworm\n"
    "FROM ${BASE_IMAGE} AS core\n"
    "FROM core AS ci\n"
    "FROM ci AS non-root\n"
)
CHECKOUT_PYPROJECT = (
    "# characterization stand-in for the ASH pyproject.toml\n"
    "[project]\n"
    'name = "automated-security-helper"\n'
    'version = "0.0.0"\n'
)
CUSTOM_CONTAINERFILE = (
    "# characterization stand-in for a custom containerfile\n"
    "ARG ASH_BASE_IMAGE\n"
    "FROM ${ASH_BASE_IMAGE}\n"
    "RUN echo custom tooling\n"
)


class _FrozenDatetime(_datetime.datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: D102 - datetime's own signature
        return FROZEN_NOW if tz is None else FROZEN_NOW.astimezone(tz)


class _Stdout:
    """``sys.stdout`` for the module under test, with a fixed ``isatty``."""

    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def __getattr__(self, name: str) -> Any:
        return getattr(sys.stdout, name)


class _Sys(types.SimpleNamespace):
    """The module's ``sys``: the real one, except ``stdout``."""

    def __init__(self, tty: bool) -> None:
        super().__init__(stdout=_Stdout(tty))

    def __getattr__(self, name: str) -> Any:
        return getattr(sys, name)


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


class IdDouble(ToolDouble):
    """``id -u`` and ``id -g``, the only forms ASH runs."""

    def __init__(self, uid: str = HOST_UID, gid: str = HOST_GID) -> None:
        self.uid = uid
        self.gid = gid

    def run(self, call: ToolCall) -> Outcome:
        if call.args == ["-u"]:
            return Exit(0, stdout=f"{self.uid}\n")
        if call.args == ["-g"]:
            return Exit(0, stdout=f"{self.gid}\n")
        raise call.reject("only id -u and id -g")


def _parse_mount(call: ToolCall, value: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for part in value.split(","):
        key, sep, item = part.partition("=")
        if not sep:
            if part != "readonly":
                raise call.reject(f"mount option {part!r}")
            fields["readonly"] = "true"
            continue
        if key not in ("type", "source", "destination"):
            raise call.reject(f"mount key {key!r}")
        fields[key] = item
    if fields.get("type") != "bind" or "source" not in fields:
        raise call.reject(f"mount {value!r} is not a bind mount with a source")
    if not call.confined(fields["source"]).is_dir():
        raise call.reject(f"mount source {fields['source']} is not a directory")
    return fields


#: Called for a run the runtime starts: the launch, mounts by destination, -e values.
OnRun = Callable[[ToolCall, Dict[str, Path], Dict[str, str]], None]


class RuntimeDouble(ToolDouble):
    """docker, finch, podman or nerdctl, as far as ASH drives them.

    ``build`` and ``buildx build`` check that ``--file`` and the context exist and
    record the tag as built. ``run`` parses the runtime's own flags up to the image,
    checks every bind mount's source, and refuses an image that was neither built
    in this scenario nor listed in ``images`` with the runtime's own message.
    ``on_run`` may write what the in-container ASH would write, through the launch's
    ``ToolCall.write``.
    """

    BUILD = ArgvGrammar(
        value_flags=frozenset(
            {
                "--build-arg",
                "--tag",
                "--target",
                "--file",
                "--cache-from",
                "--cache-to",
                "--build-context",
            }
        ),
        bool_flags=frozenset({"--no-cache", "-q", "--load"}),
        glued_flags=frozenset({"--pull"}),
        min_positionals=1,
        max_positionals=1,
    )

    def __init__(
        self,
        *,
        build: Outcome = Exit(0, stdout="Successfully built\n"),
        custom_build: Optional[Outcome] = None,
        run: Outcome = Exit(0, stdout="ASH scan complete\n"),
        buildx: Outcome = Exit(0, stdout="github.com/docker/buildx v0.17.1\n"),
        images: Sequence[str] = (),
        on_run: Optional[OnRun] = None,
    ) -> None:
        self.build = build
        self.custom_build = custom_build
        self.run_outcome = run
        self.buildx = buildx
        self.images = set(images)
        self.on_run = on_run

    def run(self, call: ToolCall) -> Outcome:
        args = call.args
        if args[:1] == ["build"]:
            return self._build(call, args[1:], buildx=False)
        if args[:2] == ["buildx", "version"] and len(args) == 2:
            return self.buildx
        if args[:2] == ["buildx", "build"]:
            if not (isinstance(self.buildx, Exit) and self.buildx.returncode == 0):
                raise call.reject("buildx build on a runtime without buildx")
            return self._build(call, args[2:], buildx=True)
        if args[:1] == ["run"]:
            return self._run(call, args[1:])
        raise call.reject("not a runtime command ASH uses")

    def _build(self, call: ToolCall, args: List[str], buildx: bool) -> Outcome:
        parsed = self.BUILD.parse(call, args)
        if parsed.has("--load") and not buildx:
            raise call.reject("--load outside buildx build")
        for flag in ("--tag", "--file"):
            if len(parsed.flags.get(flag, [])) != 1:
                raise call.reject(f"exactly one {flag} expected")
        dockerfile = parsed.last("--file")
        packaged = Path(dockerfile) == PACKAGED_DOCKERFILE
        if not packaged and not call.confined(dockerfile).is_file():
            raise call.reject(f"--file {dockerfile} is not a file")
        context = parsed.positionals[0]
        if packaged and Path(context) != PACKAGED_CONTEXT:
            raise call.reject(f"the packaged Dockerfile built with context {context}")
        if not packaged and not call.confined(context).is_dir():
            raise call.reject(f"build context {context} is not a directory")
        for value in parsed.flags.get("--build-arg", []):
            if "=" not in value:
                raise call.reject(f"--build-arg {value!r} without =")
        for value in parsed.flags.get("--pull", []):
            if value != "false":
                raise call.reject(f"--pull={value}")
        tag = parsed.last("--tag")
        custom = tag == "automated-security-helper:custom"
        outcome = self.custom_build if custom and self.custom_build else self.build
        if isinstance(outcome, Exit) and outcome.returncode == 0:
            self.images.add(tag)
        return outcome

    def _run(self, call: ToolCall, args: List[str]) -> Outcome:
        mounts: Dict[str, Path] = {}
        env: Dict[str, str] = {}
        index = 0
        while index < len(args) and args[index].startswith("-"):
            element = args[index]
            if element in ("--rm", "-t"):
                index += 1
            elif element in ("-e", "--mount"):
                if index + 1 >= len(args):
                    raise call.reject(f"{element} needs a value")
                value = args[index + 1]
                if element == "-e":
                    key, sep, item = value.partition("=")
                    if not sep:
                        raise call.reject(f"-e {value!r} without =")
                    env[key] = item
                else:
                    fields = _parse_mount(call, value)
                    mounts[fields["destination"]] = call.confined(fields["source"])
                index += 2
            elif element.startswith("--network="):
                index += 1
            else:
                raise call.reject(f"unknown run flag {element!r}")
        if index >= len(args):
            raise call.reject("run without an image")
        image, command = args[index], args[index + 1 :]
        if "--rm" not in args[:index]:
            raise call.reject("run without --rm")
        if command[:1] != ["ash"]:
            raise call.reject(f"the container command is {command[:1]}, not ash")
        if image not in self.images:
            return Exit(
                125,
                stderr=f"Unable to find image '{image}' locally\n"
                "Error: pull access denied, repository does not exist\n",
            )
        if self.on_run is not None:
            self.on_run(call, mounts, env)
        return self.run_outcome


class WrapperDouble(ToolDouble):
    """A command prefix such as ``sudo -E`` from OCI_RUNNER_WRAPPER: runs the rest."""

    def __init__(self, flags: Sequence[str] = ("-E",)) -> None:
        self.flags = list(flags)

    def run(self, call: ToolCall) -> Outcome:
        if call.args[: len(self.flags)] != self.flags:
            raise call.reject(f"expected the wrapper flags {self.flags}")
        inner = call.args[len(self.flags) :]
        if not inner:
            raise call.reject("nothing to run")
        return call.exec(inner, call.tool)


# ---------------------------------------------------------------------------
# Scenario helpers
# ---------------------------------------------------------------------------


def _checkout(char, *, pyproject: bool = True, sub: str = "") -> Path:
    """A directory holding a Dockerfile (and pyproject.toml), made the working directory.

    ``sub`` names a subdirectory to run from instead, so the lookup has to walk up.
    A plain chdir: the harness puts the working directory back when the test ends,
    before it removes the test's directory.
    """
    root = char.tmp / "checkout"
    files = {"Dockerfile": CHECKOUT_DOCKERFILE}
    if pyproject:
        files["pyproject.toml"] = CHECKOUT_PYPROJECT
    char.write_source(files, root=root)
    cwd = root / sub if sub else root
    cwd.mkdir(parents=True, exist_ok=True)
    os.chdir(cwd)
    return root


def _world(
    char,
    runtimes: Sequence[str] = ("docker",),
    double: Optional[RuntimeDouble] = None,
    *,
    on: str = "path",
    absent: Sequence[str] = (),
    id_tool: bool = True,
) -> RuntimeDouble:
    """``id`` in the system directory, the named runtimes where ``on`` says.

    Every runtime not named is declared absent. All named runtimes share one double.
    The terminal size the run forwards comes from COLUMNS and LINES, set here.
    """
    char.set_env(COLUMNS="132", LINES="43")
    if id_tool:
        char.tool("id", IdDouble(), on="sysbin")
    double = double or RuntimeDouble()
    for name in runtimes:
        char.tool(name, double, on=on)
    char.absent(*[name for name in RUNTIMES if name not in runtimes], *absent)
    return double


def _summary(result: Any) -> Dict[str, Any]:
    """The fields of a run_ash_container result a caller reads."""
    if isinstance(result, subprocess.CalledProcessError):
        args = result.cmd
        stdout = result.output
    else:
        args = result.args
        stdout = result.stdout
    return {
        "type": type(result).__name__,
        "returncode": result.returncode,
        "args": list(args) if isinstance(args, (list, tuple)) else args,
        "stdout": stdout,
        "stderr": result.stderr,
        "container_was_started": rac.container_was_started(result),
    }


def _container(char, **kwargs: Any) -> Dict[str, Any]:
    """Run ``run_ash_container`` on ``<SRC>`` into ``<OUT>`` with ``kwargs``."""
    kwargs.setdefault("source_dir", char.src)
    kwargs.setdefault("output_dir", char.out)
    char.begin()
    with char.phase("container"):
        result = rac.run_ash_container(**kwargs)
    return _summary(result)
