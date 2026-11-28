# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Install providers: the routes ``ash dependencies install`` can install a tool by.

A plugin declares how its tool is installed (``uv tool install ...``, a pinned
release download, ``gem install ...``). That declaration is one *route*. This module
names the routes as **providers** and maps a declared command onto another provider's
equivalent when the operator asks for it with ``--providers``:

- ``uv`` and ``pipx`` install Python tools into per-tool environments, ``pip`` installs
  into one interpreter, ``release-download`` is the pinned-release downloader
  (``utils/download_utils``, and ``utils/rules_bundles`` for a pinned rules bundle),
  ``nix`` realizes the repository flake's pinned toolchain, and ``apt``, ``dnf``,
  ``yum``, ``zypper``, ``brew``, ``npm``, ``pnpm``,
  ``conda``, ``choco`` and ``gem`` are one generic system-package shape
  (:class:`PackageManagerProvider`) parameterized by the manager: nothing is special
  cased per manager. ``go`` and ``cargo`` are declared stubs that refuse with "not
  implemented" so the value set says what is planned. ``custom`` is the pseudo-provider
  for a plugin's own shell or download command, which has no equivalent elsewhere.
- Providers are command BUILDERS. Nothing here runs a command, probes a tool, or reads
  a network. A provider returns the argv lists the installer's runner will run, or a
  :class:`Refusal` naming the provider and the capability it lacks. A refusal is a
  value; the installer decides what to do with it, and never retries it through
  another provider that the operator did not list.
- What a tool is called in another ecosystem comes from the install-package facet
  (``base/install_package_facets``), ASH-declared data, never read from the tree.

Selection. With ``--providers a,b,c`` the list is both a PERMISSION boundary (only
those providers may install anything this run) and an ORDER: the first listed provider
that can serve the command wins, each provider skipped on the way is reported with its
reason, and when none can the run refuses naming every provider tried. Without the
flag every provider is permitted and the order is the command's own declared provider
first, then ``uv``, then the facet's preference, so an untouched run builds exactly the
commands the plugins declared.
"""

from __future__ import annotations

import enum
import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from automated_security_helper.base.install_package_facets import (
    EcosystemPackage,
    InstallPackageFacet,
    install_package_facet,
)


class Capability(str, enum.Enum):
    """What a provider can do. A refusal names the one that is missing."""

    PYTHON_TOOL_INSTALLS = "python tool installs"
    PYTHON_ENV_INSTALLS = "python-env installs"
    INTERPRETER_REQUESTS = "interpreter requests"
    VENV_VENDING = "venv vending"
    BINARY_PINNING = "binary pinning"
    RELEASE_DOWNLOADS = "pinned release downloads"
    NATIVE_PACKAGES = "native package installs"
    PRIVILEGED_INSTALLS = "unprivileged installs"
    CUSTOM_COMMANDS = "custom install commands"
    IMPLEMENTED = "installs at all"


class CommandKind(str, enum.Enum):
    """The shape of one declared install command, as the installer recognizes it."""

    PYTHON_TOOL = "python tool"
    PYTHON_ENV = "python environment"
    RELEASE_DOWNLOAD = "release download"
    NATIVE_PACKAGE = "native package"
    OPAQUE = "opaque"
    CUSTOM = "custom"


@dataclass(frozen=True)
class EnvOptions:
    """The run's environment flags, one value for every provider."""

    inherit_system_tools: bool = True
    virtualenv_path: Optional[Path] = None
    create_virtualenv: bool = False
    #: ``scanner_key -> absolute path`` forced with ``--binary-path``.
    forced_binaries: Mapping[str, Path] = field(default_factory=dict)


@dataclass(frozen=True)
class RouteContext:
    """What a builder may read about the host. Values, never probes that run a tool."""

    platform_name: str = ""
    arch: str = ""
    bin_dir: Optional[Path] = None
    is_root: bool = False
    #: True when ``--providers`` was given.
    explicit: bool = False


@dataclass(frozen=True)
class InstallRequest:
    """One declared install command, parsed."""

    kind: CommandKind
    argv: Tuple[str, ...]
    #: The provider the plugin declared the command for.
    native_provider: str
    #: The tool's command name, for the facet lookup.
    tool: Optional[str] = None
    spec: Optional[str] = None
    runtime_request: Optional[str] = None
    with_dependencies: Tuple[str, ...] = ()
    requirements: Tuple[str, ...] = ()
    #: The interpreter an environment install targets.
    target_python: Optional[str] = None
    #: True when the plugin declared the command with ``shell=True``.
    shell: bool = False

    @property
    def subject(self) -> str:
        if self.tool:
            return self.tool
        return (
            "the command "
            + " ".join(self.argv[:3])
            + (" ..." if len(self.argv) > 3 else "")
        )


@dataclass(frozen=True)
class Refusal:
    """A provider that cannot serve a request, and the capability it lacks."""

    provider: str
    capability: Capability
    detail: str

    @property
    def text(self) -> str:
        return (
            f"{self.provider} does not support {self.capability.value} ({self.detail})"
        )


@dataclass(frozen=True)
class Route:
    """The provider chosen for one command, and the argv lists it builds."""

    provider: str
    commands: Tuple[Tuple[str, ...], ...]
    caveats: Tuple[str, ...] = ()
    #: Providers tried before this one, with the reason each was skipped.
    skipped: Tuple[Tuple[str, str], ...] = ()
    #: A route with a key is built once per run (nix realizes the whole toolchain).
    run_once_key: Optional[str] = None


@dataclass(frozen=True)
class Refused:
    """No permitted provider could serve the request."""

    subject: str
    tried: Tuple[Tuple[str, str], ...]
    providers: Tuple[str, ...]

    @property
    def text(self) -> str:
        lines = [
            (
                f"--providers {','.join(self.providers)}: no permitted provider "
                f"can install {self.subject}."
            )
        ]
        lines.extend(f"  {name}: {reason}" for name, reason in self.tried)
        lines.append(
            f"Nothing was installed for {self.subject}; no provider outside the list "
            "was tried and none was substituted."
        )
        return "\n".join(lines)


# --------------------------------------------------------------------------------------
# Recognizing a declared command
# --------------------------------------------------------------------------------------

#: argv[0] of a declared command -> the provider that owns it.
_NATIVE_MANAGERS: Dict[str, str] = {
    "apt-get": "apt",
    "apt": "apt",
    "dnf": "dnf",
    "yum": "yum",
    "zypper": "zypper",
    "brew": "brew",
    "npm": "npm",
    "pnpm": "pnpm",
    "conda": "conda",
    "choco": "choco",
    "gem": "gem",
    "go": "go",
    "cargo": "cargo",
    "pipx": "pipx",
}

_DOWNLOAD_SCRIPT_MARKER = (
    "automated_security_helper.utils.download_utils import install_"
)
_PINNED_SCRIPT_MARKER = "import install_pinned_tool"
#: The whole ``-c`` script of the command a plugin declares when it cannot install
#: its tool (``download_utils.refusing_install_command``, and opengrep's refusals of
#: a version ASH cannot verify): it writes its one argument to stderr and exits 1.
_REFUSING_SCRIPT = "import sys; sys.exit(sys.argv[1])"


def _parse_uv_tool_install(
    arguments: Sequence[str],
) -> Optional[Tuple[Optional[str], Tuple[str, ...], str]]:
    """``(runtime_request, with_dependencies, spec)`` of the one shape ASH emits.

    ``uv tool install [--python REQ] [--with DEP]* SPEC`` is what
    ``UVToolMixin._setup_uv_tool_install_commands`` and the ``uv`` package manager
    renderer produce. Anything else (another option, two specs) is not recognized,
    and the caller keeps it opaque rather than guess at it.
    """
    runtime: Optional[str] = None
    with_dependencies: List[str] = []
    positional: List[str] = []
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item in ("--python", "--with"):
            if index + 1 >= len(arguments):
                return None
            value = arguments[index + 1]
            if item == "--python":
                if runtime is not None:
                    return None
                runtime = value
            else:
                with_dependencies.append(value)
            index += 2
            continue
        if item.startswith("-"):
            return None
        positional.append(item)
        index += 1
    if len(positional) != 1:
        return None
    return runtime, tuple(with_dependencies), positional[0]


def requirement_name(spec: str) -> str:
    """The distribution name of a PEP 508 requirement, e.g. ``checkov`` for
    ``checkov>=3,<4``."""
    try:
        from packaging.requirements import Requirement

        return Requirement(spec).name
    except Exception:
        match = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", spec.strip())
        return match.group(0) if match else spec.strip()


def classify_install_command(
    argv: Sequence[str], shell: bool = False, tool_key: Optional[str] = None
) -> InstallRequest:
    """Parse one declared install command into an :class:`InstallRequest`.

    Recognition is by exact shape, the way the installer already recognizes the pinned
    download script and the two environment installs. A shape that is not recognized is
    CUSTOM (run as declared, by the ``custom`` provider) or OPAQUE (a ``uv`` command
    this parser does not understand: run as declared, by ``uv``). The pinned
    rules-bundle script (``rules_bundles.RULES_BUNDLE_INSTALL_SCRIPT``) is recognized
    the same way, as a release download.
    """
    from automated_security_helper.utils.rules_bundles import (
        RULES_BUNDLE_INSTALL_SCRIPT,
    )
    from automated_security_helper.utils.uv_tool_runner import UV_NO_CONFIG

    parts = tuple(argv)
    if shell or not parts:
        return InstallRequest(
            CommandKind.CUSTOM, parts, "custom", tool=tool_key, shell=bool(shell)
        )

    if parts[:3] == ("uv", "tool", "install"):
        parsed = _parse_uv_tool_install(parts[3:])
        if parsed is None:
            return InstallRequest(CommandKind.OPAQUE, parts, "uv", tool=tool_key)
        runtime, with_dependencies, spec = parsed
        return InstallRequest(
            CommandKind.PYTHON_TOOL,
            parts,
            "uv",
            tool=tool_key or requirement_name(spec),
            spec=spec,
            runtime_request=runtime,
            with_dependencies=with_dependencies,
        )

    if parts[:4] == (sys.executable, "-m", "pip", "install"):
        return InstallRequest(
            CommandKind.PYTHON_ENV,
            parts,
            "pip",
            tool=tool_key,
            requirements=parts[4:],
            target_python=sys.executable,
        )
    if parts[:6] == ("uv", "pip", "install", UV_NO_CONFIG, "--python", sys.executable):
        return InstallRequest(
            CommandKind.PYTHON_ENV,
            parts,
            "uv",
            tool=tool_key,
            requirements=parts[6:],
            target_python=sys.executable,
        )

    if (
        len(parts) > 2
        and parts[0] == sys.executable
        and parts[1] == "-c"
        and _DOWNLOAD_SCRIPT_MARKER in parts[2]
    ):
        tool = tool_key
        if _PINNED_SCRIPT_MARKER in parts[2] and len(parts) > 3:
            tool = parts[3]
        return InstallRequest(
            CommandKind.RELEASE_DOWNLOAD, parts, "release-download", tool=tool
        )

    if (
        len(parts) == 4
        and parts[0] == sys.executable
        and parts[1] == "-c"
        and parts[2] == RULES_BUNDLE_INSTALL_SCRIPT
    ):
        # A pinned rules bundle (cfn-guard's rules registry) is a release download
        # too: its archive is pinned by SHA-256 in utils/tool_downloads.py beside the
        # binary pins. Matched by its exact script, so release-download runs it as
        # declared; release-download refuses a custom command it does not recognize.
        return InstallRequest(
            CommandKind.RELEASE_DOWNLOAD, parts, "release-download", tool=tool_key
        )

    owner = _NATIVE_MANAGERS.get(os.path.basename(parts[0]))
    if owner is not None:
        return InstallRequest(CommandKind.NATIVE_PACKAGE, parts, owner, tool=tool_key)

    return InstallRequest(CommandKind.CUSTOM, parts, "custom", tool=tool_key)


# --------------------------------------------------------------------------------------
# Virtualenv helpers (file reads only; nothing is executed)
# --------------------------------------------------------------------------------------


def venv_python(path: Path) -> Path:
    """The interpreter inside the virtualenv at ``path``."""
    if sys.platform == "win32":
        return path / "Scripts" / "python.exe"
    return path / "bin" / "python"


def venv_scripts_dir(path: Path) -> Path:
    """The directory a virtualenv puts its installed commands in."""
    return path / ("Scripts" if sys.platform == "win32" else "bin")


def is_virtualenv(path: Path) -> bool:
    """Whether ``path`` is a virtualenv: a directory holding ``pyvenv.cfg``."""
    try:
        return path.is_dir() and (path / "pyvenv.cfg").is_file()
    except OSError:
        return False


def pyvenv_cfg_version(path: Path) -> Optional[str]:
    """The Python version ``path/pyvenv.cfg`` records, or None when it names none.

    A file read, so the answer needs no execution of the environment's interpreter.
    ``venv`` writes ``version``; uv writes ``version_info``.
    """
    try:
        with open(path / "pyvenv.cfg", "r", encoding="utf-8", errors="replace") as f:
            text = f.read(65536)
    except OSError:
        return None
    found: Dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            found[key.strip().lower()] = value.strip()
    version = found.get("version_info") or found.get("version")
    if version and re.match(r"\d+\.\d+", version):
        return version
    return None


def request_satisfied(request: str, version: str) -> Optional[bool]:
    """Whether Python ``version`` meets the interpreter ``request``, None if unjudgeable.

    A request is a PEP 440 specifier (``>=3.10,<3.14``) or a bare version (``3.12``).
    Anything else (``cpython@3.12``, a path) cannot be judged from a version string,
    and the caller refuses rather than assume it holds.
    """
    request = request.strip()
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        if re.fullmatch(r"\d+(\.\d+){0,2}", request):
            return version == request or version.startswith(request + ".")
        return SpecifierSet(request).contains(Version(version), prereleases=True)
    except Exception:
        return None


def joined_runtime_request(
    requests: Iterable[Optional[str]],
) -> Tuple[Optional[str], Optional[str]]:
    """The one interpreter request that satisfies every tool's, or why none can.

    Specifier requests are concatenated (``>=3.10,<3.15`` and ``>=3.10,<3.14`` give
    ``>=3.10,<3.15,>=3.10,<3.14``), which uv resolves or refuses loudly when no
    interpreter meets all of them. No tool's request is dropped. A bare version cannot
    be joined with a different request, so mixed forms are reported.
    """
    distinct = list(dict.fromkeys(r.strip() for r in requests if r and r.strip()))
    if not distinct:
        return None, None
    if len(distinct) == 1:
        return distinct[0], None
    bare = [r for r in distinct if re.fullmatch(r"\d+(\.\d+){0,2}", r)]
    if bare:
        return None, (
            "the tools' interpreter requests cannot be joined: "
            + ", ".join(distinct)
            + " (a bare version cannot be combined with another request)"
        )
    return ",".join(distinct), None


# --------------------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------------------

_SPECIFIER_CHARS = re.compile(r"[<>=!~,]")


class InstallProvider:
    """One route a tool can be installed by. Subclasses build commands; none run any."""

    name: str = ""
    description: str = ""
    implemented: bool = True

    def capabilities(self) -> frozenset:
        return frozenset()

    def build(
        self,
        request: InstallRequest,
        env: EnvOptions,
        row: Optional[EcosystemPackage],
        context: RouteContext,
    ) -> "List[List[str]] | Refusal":
        raise NotImplementedError

    def venv_create_command(
        self, path: Path, runtime_request: Optional[str]
    ) -> "List[str] | Refusal":
        return Refusal(
            self.name,
            Capability.VENV_VENDING,
            "this provider does not create virtualenvs",
        )

    # The declared command, unchanged, when this provider is the one it was declared
    # for. The default run is built from this, so it is byte-for-byte what plugins
    # declared.
    def _identity(self, request: InstallRequest) -> List[List[str]]:
        return [list(request.argv)]


class UvProvider(InstallProvider):
    name = "uv"
    description = "uv tool environments, uv pip installs, uv venv"

    def capabilities(self) -> frozenset:
        return frozenset(
            {
                Capability.PYTHON_TOOL_INSTALLS,
                Capability.PYTHON_ENV_INSTALLS,
                Capability.INTERPRETER_REQUESTS,
                Capability.VENV_VENDING,
            }
        )

    def build(self, request, env, row, context):
        from automated_security_helper.utils.uv_tool_runner import UV_NO_CONFIG

        venv = env.virtualenv_path
        if request.kind == CommandKind.OPAQUE and request.native_provider == self.name:
            return self._identity(request)
        if request.kind == CommandKind.PYTHON_TOOL:
            if venv is None:
                return self._identity(request)
            return [
                [
                    "uv",
                    "pip",
                    "install",
                    UV_NO_CONFIG,
                    "--python",
                    str(venv_python(venv)),
                    request.spec or "",
                    *request.with_dependencies,
                ]
            ]
        if request.kind == CommandKind.PYTHON_ENV:
            # "Into the environment running ASH" (``PackageManager.PIP``): a
            # PYTHON_ENV install exists so ASH's own process can import the
            # packages (cdk-nag's aws-cdk-lib). It is never rerouted into the
            # --virtualenv-path virtualenv: ASH's interpreter cannot import from
            # there, so the install would read INSTALLED and the next scan
            # MISSING, and a uv-vended virtualenv ships no pip for the pip form.
            if request.native_provider == self.name:
                return self._identity(request)
            if not context.explicit:
                return self._identity(request)
            return [
                [
                    "uv",
                    "pip",
                    "install",
                    UV_NO_CONFIG,
                    "--python",
                    request.target_python or sys.executable,
                    *request.requirements,
                ]
            ]
        return Refusal(
            self.name,
            Capability.PYTHON_TOOL_INSTALLS,
            f"the declared install is a {request.kind.value}, not a Python package",
        )

    def venv_create_command(self, path, runtime_request):
        command = ["uv", "venv"]
        if runtime_request:
            command += ["--python", runtime_request]
        command.append(str(path))
        return command


class PipxProvider(InstallProvider):
    name = "pipx"
    description = "pipx per-tool environments"

    def capabilities(self) -> frozenset:
        return frozenset(
            {Capability.PYTHON_TOOL_INSTALLS, Capability.INTERPRETER_REQUESTS}
        )

    def build(self, request, env, row, context):
        if request.native_provider == self.name and request.kind in (
            CommandKind.NATIVE_PACKAGE,
            CommandKind.OPAQUE,
        ):
            return self._identity(request)
        if request.kind == CommandKind.PYTHON_ENV:
            return Refusal(
                self.name,
                Capability.PYTHON_ENV_INSTALLS,
                "pipx installs only into its own per-tool environments",
            )
        if request.kind != CommandKind.PYTHON_TOOL:
            return Refusal(
                self.name,
                Capability.PYTHON_TOOL_INSTALLS,
                f"the declared install is a {request.kind.value}, not a Python package",
            )
        if env.virtualenv_path is not None:
            return Refusal(
                self.name,
                Capability.PYTHON_ENV_INSTALLS,
                "installing into the virtualenv named by --virtualenv-path; pipx "
                "manages only its own per-tool environments",
            )
        runtime = request.runtime_request
        if runtime and _SPECIFIER_CHARS.search(runtime):
            # pipx's --python takes an executable name, a version (3.11) or a path;
            # it documents no version-range form (pipx CLI reference, `pipx install`).
            return Refusal(
                self.name,
                Capability.INTERPRETER_REQUESTS,
                f"an interpreter request given as a version range ('{runtime}'); "
                "pipx --python takes an executable, a version or a path",
            )
        command = ["pipx", "install"]
        if runtime:
            command += ["--python", runtime]
        command.append(request.spec or "")
        commands = [command]
        if request.with_dependencies:
            package = requirement_name(request.spec or "")
            commands.extend(
                ["pipx", "inject", package, dependency]
                for dependency in request.with_dependencies
            )
        return commands


class PipProvider(InstallProvider):
    name = "pip"
    description = "pip into one interpreter's environment, python -m venv"

    def capabilities(self) -> frozenset:
        return frozenset(
            {
                Capability.PYTHON_TOOL_INSTALLS,
                Capability.PYTHON_ENV_INSTALLS,
                Capability.VENV_VENDING,
            }
        )

    def build(self, request, env, row, context):
        venv = env.virtualenv_path
        python = str(venv_python(venv)) if venv else None
        if request.kind == CommandKind.PYTHON_ENV:
            # Stays on ASH's own interpreter, never the --virtualenv-path
            # virtualenv: see the UvProvider PYTHON_ENV arm for why.
            if request.native_provider == self.name:
                return self._identity(request)
            return [
                [
                    request.target_python or sys.executable,
                    "-m",
                    "pip",
                    "install",
                    *request.requirements,
                ]
            ]
        if request.kind == CommandKind.PYTHON_TOOL:
            if request.runtime_request and venv is None:
                return Refusal(
                    self.name,
                    Capability.INTERPRETER_REQUESTS,
                    f"an interpreter request ('{request.runtime_request}') with no "
                    "--virtualenv-path; pip installs into the interpreter running ASH "
                    "and cannot choose another",
                )
            return [
                [
                    python or sys.executable,
                    "-m",
                    "pip",
                    "install",
                    request.spec or "",
                    *request.with_dependencies,
                ]
            ]
        return Refusal(
            self.name,
            Capability.PYTHON_TOOL_INSTALLS,
            f"the declared install is a {request.kind.value}, not a Python package",
        )

    def venv_create_command(self, path, runtime_request):
        if runtime_request:
            return Refusal(
                self.name,
                Capability.INTERPRETER_REQUESTS,
                f"an interpreter request ('{runtime_request}') for a new virtualenv; "
                "python -m venv uses the interpreter running ASH",
            )
        return [sys.executable, "-m", "venv", str(path)]


class ReleaseDownloadProvider(InstallProvider):
    name = "release-download"
    description = "ASH's pinned, digest-verified release downloads"

    def capabilities(self) -> frozenset:
        return frozenset({Capability.RELEASE_DOWNLOADS, Capability.BINARY_PINNING})

    def build(self, request, env, row, context):
        if request.kind == CommandKind.RELEASE_DOWNLOAD:
            return self._identity(request)
        tool = request.tool
        from automated_security_helper.utils.tool_downloads import (
            downloadable_tools,
            supported_platforms,
        )

        if not tool or tool not in downloadable_tools():
            return Refusal(
                self.name,
                Capability.RELEASE_DOWNLOADS,
                f"{tool or request.subject} has no pinned release asset "
                "(tool_downloads)",
            )
        if request.kind == CommandKind.CUSTOM:
            # A custom command is not rebuilt from its tool's name: rebuilt, it was
            # one more download of the binary, and the command it stood for never
            # ran. The one ASH declares when a plugin cannot install its tool
            # installs nothing (it writes why and exits 1), so it runs as declared
            # and the run fails with its reason. Any other custom command is the
            # plugin's own shell or download command, which only the custom provider
            # runs: refused here, it runs when custom is listed, and nothing runs
            # when it is not. (A pinned rules bundle is a release download, served
            # above.)
            argv = request.argv
            if (
                not request.shell
                and len(argv) == 4
                and argv[0] == sys.executable
                and argv[1] == "-c"
                and argv[2] == _REFUSING_SCRIPT
            ):
                return self._identity(request)
            return Refusal(
                self.name,
                Capability.CUSTOM_COMMANDS,
                "the declared command is the plugin's own, not a pinned release "
                "download; list custom to run it as declared",
            )
        pairs = [tuple(p) for p in supported_platforms(tool)]
        if (context.platform_name, context.arch) not in pairs:
            return Refusal(
                self.name,
                Capability.RELEASE_DOWNLOADS,
                f"{tool} publishes no pinned asset for {context.platform_name}/"
                f"{context.arch}",
            )
        from automated_security_helper.utils.download_utils import (
            create_pinned_tool_install_command,
        )

        command = create_pinned_tool_install_command(
            tool,
            context.platform_name,
            context.arch,
            str(context.bin_dir) if context.bin_dir is not None else None,
        )
        return [list(command.args)]


class NixProvider(InstallProvider):
    name = "nix"
    description = "the repository flake's pinned toolchain (`ash --mode nix`)"

    def capabilities(self) -> frozenset:
        return frozenset({Capability.BINARY_PINNING, Capability.NATIVE_PACKAGES})

    def build(self, request, env, row, context):
        if row is None:
            return Refusal(
                self.name,
                Capability.NATIVE_PACKAGES,
                f"the install-package facet has no nix row for {request.subject}",
            )
        if env.virtualenv_path is not None and request.kind in (
            CommandKind.PYTHON_TOOL,
            CommandKind.PYTHON_ENV,
        ):
            return Refusal(
                self.name,
                Capability.PYTHON_ENV_INSTALLS,
                "installing into the virtualenv named by --virtualenv-path; the flake "
                "supplies its own pinned tool environments",
            )
        if request.runtime_request:
            return Refusal(
                self.name,
                Capability.INTERPRETER_REQUESTS,
                f"an interpreter request ('{request.runtime_request}'); the flake "
                "pins the interpreter each tool runs on",
            )
        if request.spec and "==" in request.spec:
            return Refusal(
                self.name,
                Capability.BINARY_PINNING,
                f"an exact version pin ('{request.spec}'); the flake lock pins the "
                "whole toolchain and nix serves no per-tool version here",
            )
        from automated_security_helper.interactions.run_ash_nix import (
            _EXPERIMENTAL_FEATURES,
            resolve_flake_ref,
        )
        from automated_security_helper.utils.subprocess_utils import find_executable

        nix = find_executable("nix")
        if nix is None:
            return Refusal(
                self.name,
                Capability.NATIVE_PACKAGES,
                "nix was not found on PATH (install it from https://nixos.org/download/)",
            )
        flake_ref = resolve_flake_ref()
        return [
            [
                nix,
                "--extra-experimental-features",
                _EXPERIMENTAL_FEATURES,
                "develop",
                flake_ref,
                "--command",
                "python3",
                "-c",
                "pass",
            ]
        ]

    def run_once_key(self) -> str:
        from automated_security_helper.interactions.run_ash_nix import (
            resolve_flake_ref,
        )

        return f"nix:{resolve_flake_ref()}"


class PackageManagerProvider(InstallProvider):
    """One generic system-package shape, parameterized by the manager.

    ``install_prefix`` is the manager's install verb with its non-interactive flags;
    ``privileged`` is DECLARED, not assumed: a manager declared privileged refuses to
    build when the run is not root, so ASH never invents a ``sudo`` wrapper. A package
    comes from the facet row for the tool; a manager with no row for it refuses,
    naming the missing row. The declared command is the identity when the plugin
    declared it for this manager.
    """

    def __init__(
        self,
        name: str,
        install_prefix: Sequence[str],
        *,
        privileged: bool,
        description: str,
    ) -> None:
        self.name = name
        self.install_prefix = tuple(install_prefix)
        self.privileged = privileged
        self.description = description

    def capabilities(self) -> frozenset:
        caps = {Capability.NATIVE_PACKAGES}
        if not self.privileged:
            caps.add(Capability.PRIVILEGED_INSTALLS)
        return frozenset(caps)

    def build(self, request, env, row, context):
        if (
            request.kind in (CommandKind.NATIVE_PACKAGE, CommandKind.OPAQUE)
            and request.native_provider == self.name
        ):
            return self._identity(request)
        if request.kind == CommandKind.PYTHON_ENV or (
            env.virtualenv_path is not None and request.kind == CommandKind.PYTHON_TOOL
        ):
            return Refusal(
                self.name,
                Capability.PYTHON_ENV_INSTALLS,
                "a system package is installed system-wide, not into the Python "
                "environment or the virtualenv ASH was pointed at",
            )
        if row is None:
            return Refusal(
                self.name,
                Capability.NATIVE_PACKAGES,
                f"the install-package facet has no {self.name} row for "
                f"{request.subject}",
            )
        if self.privileged and not context.is_root:
            return Refusal(
                self.name,
                Capability.PRIVILEGED_INSTALLS,
                f"{self.name} installs system packages as root and this run is not "
                "root; ASH does not add sudo",
            )
        return [[*self.install_prefix, row.package]]


class StubProvider(InstallProvider):
    """A provider the value set names for the roadmap; building with it refuses."""

    implemented = False

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description

    def build(self, request, env, row, context):
        if request.native_provider == self.name:
            return self._identity(request)
        return Refusal(
            self.name,
            Capability.IMPLEMENTED,
            f"{self.name} is not implemented in this version of ASH; the name is "
            "declared so the --providers value set shows what is planned",
        )


class CustomProvider(InstallProvider):
    name = "custom"
    description = "a plugin's own shell or download command, run as declared"

    def capabilities(self) -> frozenset:
        return frozenset({Capability.CUSTOM_COMMANDS})

    def build(self, request, env, row, context):
        if request.native_provider == self.name:
            return self._identity(request)
        return Refusal(
            self.name,
            Capability.CUSTOM_COMMANDS,
            "custom commands are run only as the plugin declared them",
        )


def _registry() -> Dict[str, InstallProvider]:
    providers: List[InstallProvider] = [
        UvProvider(),
        PipxProvider(),
        PipProvider(),
        ReleaseDownloadProvider(),
        NixProvider(),
        PackageManagerProvider(
            "apt",
            ("apt-get", "install", "-y"),
            privileged=True,
            description="Debian and Ubuntu packages",
        ),
        PackageManagerProvider(
            "dnf",
            ("dnf", "install", "-y"),
            privileged=True,
            description="Fedora and Red Hat packages",
        ),
        PackageManagerProvider(
            "yum",
            ("yum", "install", "-y"),
            privileged=True,
            description="Amazon Linux and older Red Hat packages",
        ),
        PackageManagerProvider(
            "zypper",
            ("zypper", "--non-interactive", "install"),
            privileged=True,
            description="SUSE packages",
        ),
        PackageManagerProvider(
            "brew",
            ("brew", "install"),
            privileged=False,
            description="Homebrew formulae",
        ),
        PackageManagerProvider(
            "npm",
            ("npm", "install", "-g"),
            privileged=False,
            description="npm packages, global",
        ),
        PackageManagerProvider(
            "pnpm",
            ("pnpm", "add", "-g"),
            privileged=False,
            description="pnpm packages, global",
        ),
        PackageManagerProvider(
            "conda",
            ("conda", "install", "-y"),
            privileged=False,
            description="conda packages",
        ),
        PackageManagerProvider(
            "choco",
            ("choco", "install", "-y"),
            privileged=False,
            description="Chocolatey packages",
        ),
        PackageManagerProvider(
            "gem",
            ("gem", "install"),
            privileged=False,
            description="RubyGems",
        ),
        StubProvider("go", "`go install` of a Go tool"),
        StubProvider("cargo", "`cargo install` of a Rust tool"),
        CustomProvider(),
    ]
    return {provider.name: provider for provider in providers}


INSTALL_PROVIDERS: Mapping[str, InstallProvider] = _registry()

#: The names ``--providers`` accepts, in the order the help lists them.
KNOWN_PROVIDERS: Tuple[str, ...] = tuple(INSTALL_PROVIDERS)


def parse_providers(value: Optional[str]) -> Tuple[Optional[List[str]], Optional[str]]:
    """``(providers, error)`` for a ``--providers`` value.

    None (flag absent) means every provider is permitted in the default order. A
    blank value, an empty entry or an unknown name is an error naming the known set.
    Names are case-insensitive and a repeated name keeps its first position.
    """
    if value is None:
        return None, None
    names = [part.strip().lower() for part in value.split(",")]
    if not value.strip() or any(not name for name in names):
        return None, (
            "--providers needs a comma-separated list of provider names with no "
            f"empty entry. Known providers: {', '.join(KNOWN_PROVIDERS)}."
        )
    unknown = [name for name in names if name not in INSTALL_PROVIDERS]
    if unknown:
        return None, (
            f"Unknown provider(s) in --providers: {', '.join(dict.fromkeys(unknown))}. "
            f"Known providers: {', '.join(KNOWN_PROVIDERS)}."
        )
    return list(dict.fromkeys(names)), None


def candidate_order(
    providers: Optional[Sequence[str]],
    native_provider: str,
    facet: Optional[InstallPackageFacet],
) -> List[str]:
    """The providers to try, in order, for one command."""
    if providers is not None:
        return list(providers)
    order = [native_provider, "uv"]
    if facet is not None:
        order.extend(facet.preference)
    return [name for name in dict.fromkeys(order) if name in INSTALL_PROVIDERS]


def route_install(
    request: InstallRequest,
    env: EnvOptions,
    *,
    providers: Optional[Sequence[str]],
    context: RouteContext,
) -> "Route | Refused":
    """Choose the provider for ``request`` and build its commands.

    The first provider in :func:`candidate_order` whose builder returns commands wins.
    Every provider skipped on the way keeps its reason on the route, and when none
    builds, the :class:`Refused` carries every reason. Nothing is run, and a refused
    request is never handed to a provider outside the candidate list.
    """
    facet = install_package_facet(request.tool)
    tried: List[Tuple[str, str]] = []
    for name in candidate_order(providers, request.native_provider, facet):
        provider = INSTALL_PROVIDERS[name]
        row = facet.row_for(name) if facet is not None else None
        built = provider.build(request, env, row, context)
        if isinstance(built, Refusal):
            tried.append((name, built.text))
            continue
        caveats: Tuple[str, ...] = ()
        if row is not None and row.caveat and request.native_provider != name:
            caveats = (row.caveat,)
        dropped = _dropped_by_system_manager(request, provider)
        if dropped is not None:
            caveats = (*caveats, dropped)
        key = provider.run_once_key() if isinstance(provider, NixProvider) else None
        return Route(
            provider=name,
            commands=tuple(tuple(command) for command in built),
            caveats=caveats,
            skipped=tuple(tried),
            run_once_key=key,
        )
    return Refused(
        subject=request.subject,
        tried=tuple(tried),
        providers=tuple(providers) if providers is not None else KNOWN_PROVIDERS,
    )


def _dropped_by_system_manager(
    request: InstallRequest, provider: InstallProvider
) -> Optional[str]:
    """What a system package manager cannot honor from the declared install, or None.

    A Python tool routed to a system manager is installed as ``[*install_prefix,
    row.package]``, which carries neither the declared interpreter request nor the
    ``--with`` dependencies. The operator chose the manager, so the drop is named
    on the route rather than made silently; the facet row's own caveat covers only
    the version range.
    """
    if not isinstance(provider, PackageManagerProvider):
        return None
    if request.kind != CommandKind.PYTHON_TOOL:
        return None
    dropped: List[str] = []
    if request.runtime_request:
        dropped.append(f"the interpreter request ('{request.runtime_request}')")
    if request.with_dependencies:
        dropped.append(
            "the --with dependencies (" + ", ".join(request.with_dependencies) + ")"
        )
    if not dropped:
        return None
    return (
        f"{provider.name} installs {request.subject} as a system package and does "
        "not honor " + " or ".join(dropped) + " from the declared install"
    )


def venue_for_virtualenv(
    providers: Optional[Sequence[str]],
) -> Tuple[Optional[InstallProvider], List[Tuple[str, str]]]:
    """The first permitted provider able to vend a virtualenv, and the skips before it."""
    order = list(providers) if providers is not None else ["uv", "pip"]
    skipped: List[Tuple[str, str]] = []
    for name in order:
        provider = INSTALL_PROVIDERS[name]
        if Capability.VENV_VENDING in provider.capabilities():
            return provider, skipped
        skipped.append(
            (
                name,
                Refusal(
                    name,
                    Capability.VENV_VENDING,
                    "this provider does not create virtualenvs",
                ).text,
            )
        )
    return None, skipped


# --------------------------------------------------------------------------------------
# --binary-path
# --------------------------------------------------------------------------------------

FORCED_BINARIES_RECORD = "forced-binaries.json"

#: The names Windows starts a file under: ``.exe`` and ``.com`` images, which
#: ``CreateProcess`` runs, and the ``.bat`` and ``.cmd`` files it runs through
#: cmd.exe. A file with any other name, a shell script with a shebang line or a text
#: file, is not a program there (``[WinError 193] %1 is not a valid Win32
#: application``).
WINDOWS_PROGRAM_SUFFIXES = (".exe", ".com", ".bat", ".cmd")


def _executable_by_this_process(path: Path, info: os.stat_result) -> bool:
    """Whether the file at ``path``, with ``info`` its open descriptor's stat, is a
    program this process can start.

    POSIX: the execute bits on ``info`` and the kernel's access check
    (``download_utils._executable_by_caller``). Windows keeps no execute permission
    a check can read there: ``os.access(X_OK)`` is true of every file that exists,
    and a descriptor's stat carries no execute bits, so the bits test would refuse
    every file. What says a file is a program on Windows is its name
    (:data:`WINDOWS_PROGRAM_SUFFIXES`), the name of the path being judged, so a file
    swapped in at that path cannot change the answer.
    """
    if sys.platform == "win32":
        return path.suffix.lower() in WINDOWS_PROGRAM_SUFFIXES
    from automated_security_helper.utils import download_utils as du

    return du._executable_by_caller(path, info)


@dataclass(frozen=True)
class ForcedBinary:
    """One validated ``--binary-path`` entry."""

    scanner_key: str
    path: Path
    sha256: str


def parse_binary_path_entries(
    entries: Sequence[str],
) -> Tuple[Dict[str, str], List[str]]:
    """``({key: path_text}, errors)`` for the raw ``--binary-path`` values.

    The split is on the first ``=``. An empty key, a missing ``=``, an empty path
    (the eraser, see :func:`erase_entries`) is reported by the caller, and a scanner
    named twice is an error: one binary per scanner.
    """
    parsed: Dict[str, str] = {}
    errors: List[str] = []
    for entry in entries:
        key, sep, value = entry.partition("=")
        key = key.strip()
        if not sep or not key:
            errors.append(
                f"--binary-path {entry!r} is not <scanner>=<absolute path> "
                "(for example --binary-path checkov=/opt/tools/checkov)"
            )
            continue
        if key in parsed:
            errors.append(
                f"--binary-path names {key} more than once; one binary per scanner"
            )
            continue
        parsed[key] = value
    return parsed, errors


def in_tree_path_refusal(
    shown: str, path: Path, source_dir: Optional[Path]
) -> Optional[str]:
    """The refusal for ``path`` sitting inside the scanned tree, or None.

    None when the path is outside ``source_dir``, when ``source_dir`` is unknown,
    or when the in-tree opt-in (``ASH_ALLOW_IN_TREE_TOOLS``) admits it. The tree
    is untrusted: a flag that points the installer at a file the tree can supply
    (a forced binary, a virtualenv whose interpreter the install commands
    execute) must refuse it, or the flag becomes the way around that refusal.
    Judged on realpaths, the way the scan-time in-tree refusal judges a lookup.
    """
    from automated_security_helper.utils.subprocess_utils import (
        ALLOW_IN_TREE_TOOLS_ENV,
        parse_allow_in_tree_tools,
    )

    if source_dir is None:
        return None
    try:
        inside = os.path.commonpath(
            [os.path.realpath(path), os.path.realpath(source_dir)]
        ) == os.path.realpath(source_dir)
    except ValueError:
        inside = False
    if not inside:
        return None
    # The ONE reading of the opt-in (``parse_allow_in_tree_tools``), shared with
    # the scan-time lookups: a second inline tuple here accepted a different set
    # ("on" opted the scan in and not the installer), so an operator's value was
    # honored by one check and refused by the other.
    if parse_allow_in_tree_tools(os.environ.get(ALLOW_IN_TREE_TOOLS_ENV)):
        return None
    return (
        f"{shown}: the path is inside the scanned source tree, which ASH "
        f"does not trust to supply a binary; move it outside the tree or "
        f"set {ALLOW_IN_TREE_TOOLS_ENV}=1"
    )


def validate_forced_binary(
    key: str, path_text: str, source_dir: Optional[Path] = None
) -> "ForcedBinary | str":
    """Validate one forced binary, returning it or the refusal text.

    The path must be absolute, name a regular file that is not a symlink, and be
    executable by this process (:func:`_executable_by_this_process`; on Windows, a
    name Windows starts as a program). All three are judged on ONE open descriptor
    (``O_NOFOLLOW``), the way the pinned-copy check judges a candidate, so a link
    swapped in after the check is not followed. The file is hashed (read), never run,
    and a path inside the scanned tree is refused unless the in-tree opt-in is set:
    the tree is untrusted, and this flag must not become the way around that.
    """
    from automated_security_helper.utils import download_utils as du

    shown = f"--binary-path {key}={path_text}"
    if not path_text:
        return f"{shown}: the path is empty"
    if not os.path.isabs(path_text) and not Path(path_text).is_absolute():
        return f"{shown}: the path is not absolute"
    path = Path(path_text)
    refusal = in_tree_path_refusal(shown, path, source_dir)
    if refusal is not None:
        return refusal
    try:
        if path.is_symlink():
            return f"{shown}: the path is a symlink; name the file itself"
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except FileNotFoundError:
        return f"{shown}: the path does not exist"
    except OSError as e:
        # Windows opens no directory with os.open (it answers EACCES), so there a
        # directory is refused here and not by the S_ISREG check below. It is named
        # for what it is; the answer only words a refusal, it never admits a path.
        if os.path.isdir(path):
            return f"{shown}: the path is not a regular file"
        return f"{shown}: the path cannot be opened ({e.strerror or e})"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return f"{shown}: the path is not a regular file"
        if not _executable_by_this_process(path, info):
            return f"{shown}: the file is not executable"
        digest = du._sha256_of_open_file(fd)
    except OSError as e:
        return f"{shown}: the file cannot be read ({e.strerror or e})"
    finally:
        os.close(fd)
    return ForcedBinary(scanner_key=key, path=path, sha256=digest)


def forced_binary_still_usable(binary: ForcedBinary) -> bool:
    """Whether the forced file is still the file that was validated (never executed).

    A regular, executable, non-symlink file whose bytes still hash to the SHA-256
    the validation recorded: the one integrity datum ``--binary-path`` collects is
    re-checked wherever a decision rests on the force, so a content replacement at
    the same path between validation and that decision does not pass as the
    validated binary. Judged on one open descriptor, as the validation judged it.
    """
    from automated_security_helper.utils import download_utils as du

    try:
        if binary.path.is_symlink():
            return False
        fd = os.open(
            binary.path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return False
        if not _executable_by_this_process(binary.path, info):
            return False
        return du._sha256_of_open_file(fd) == binary.sha256.lower()
    except OSError:
        return False
    finally:
        os.close(fd)


def forced_binaries_record_path() -> Path:
    """Where forced binaries are recorded: the install-receipt store."""
    from automated_security_helper.utils.download_utils import receipt_root

    return receipt_root() / FORCED_BINARIES_RECORD


def read_forced_binaries() -> Dict[str, Dict[str, Any]]:
    """The recorded forced binaries, ``{scanner_key: entry}``; empty when none."""
    try:
        data = json.loads(forced_binaries_record_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    entries = data.get("binaries") if isinstance(data, dict) else None
    return dict(entries) if isinstance(entries, dict) else {}


def recorded_forced_binary(scanner_key: str) -> Optional[ForcedBinary]:
    """The recorded ``--binary-path`` force for ``scanner_key``, still usable.

    The production reader of the record :func:`record_forced_binaries` writes --
    what "the path is recorded for dependency validation" promises: the scanners'
    dependency validation and a later ``ash dependencies install`` run consult
    this before any PATH or uv lookup. None when no entry names the scanner, the
    entry does not parse, or the file is no longer the one the flag validated
    (:func:`forced_binary_still_usable`: moved, not a regular executable file, a
    symlink, or content that no longer hashes to the recorded SHA-256) -- a stale
    record is set aside, never trusted by its path alone. The file is read and
    hashed here, never executed.
    """
    if not scanner_key:
        return None
    entry = read_forced_binaries().get(scanner_key)
    if not isinstance(entry, dict):
        return None
    path_text = entry.get("path")
    digest = entry.get("sha256")
    if not isinstance(path_text, str) or not path_text or not isinstance(digest, str):
        return None
    binary = ForcedBinary(
        scanner_key=scanner_key, path=Path(path_text), sha256=digest.lower()
    )
    return binary if forced_binary_still_usable(binary) else None


def record_forced_binaries(
    binaries: Iterable[ForcedBinary], erase: Iterable[str] = ()
) -> Path:
    """Record forced binaries in the receipt store and return the record's path.

    One JSON document, written atomically. A run with no ``--binary-path`` never
    calls this, so records persist until the operator replaces or erases them
    (``--binary-path <scanner>=`` with an empty path).
    """
    import datetime

    from automated_security_helper.utils.atomic_write import write_text_atomically
    from automated_security_helper.utils.download_utils import _private_dir

    path = forced_binaries_record_path()
    _private_dir(path.parent)
    entries = read_forced_binaries()
    for key in erase:
        entries.pop(key, None)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for binary in binaries:
        entries[binary.scanner_key] = {
            "scanner_key": binary.scanner_key,
            "path": str(binary.path),
            "sha256": binary.sha256,
            "recorded_at": now,
            "recorded_by": "ash dependencies install",
        }
    write_text_atomically(
        path, json.dumps({"binaries": entries}, indent=2, sort_keys=True) + "\n"
    )
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    return path
